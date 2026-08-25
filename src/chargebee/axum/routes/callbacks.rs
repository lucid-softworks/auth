use super::super::{ChargebeeRouteState, input, support};
use axum::{
    Extension,
    extract::Query,
    http::HeaderMap,
    response::Response,
    routing::{MethodRouter, get},
};
use chrono::Utc;
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

pub(super) fn success_route() -> MethodRouter {
    get(success)
}

pub(super) fn cancel_route() -> MethodRouter {
    get(cancel)
}

async fn success(
    Extension(service): Extension<Arc<crate::AuthService>>,
    headers: HeaderMap,
    Query(query): Query<input::CallbackQuery>,
) -> Response {
    let callback = query
        .callback_url
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    if let Err(response) = support::validate_origin(&service, &headers, callback) {
        return response;
    }
    support::redirect(support::absolute_url(&service, &headers, callback))
}

async fn cancel(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<ChargebeeRouteState>,
    headers: HeaderMap,
    Query(query): Query<input::CallbackQuery>,
) -> Response {
    let callback = query
        .callback_url
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    if let Err(response) = support::validate_origin(&service, &headers, callback) {
        return response;
    }
    let redirect = || support::redirect(support::absolute_url(&service, &headers, callback));
    let Some(subscription_id) = query
        .subscription_id
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return redirect();
    };
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return redirect();
    };
    let has_customer = support::session_customer_id(&session).is_some();
    if !has_customer {
        return redirect();
    }
    if let Err(error) = synchronize(&state, subscription_id).await {
        tracing::error!(message = %error, "Error in cancel subscription callback");
    }
    redirect()
}

async fn synchronize(state: &ChargebeeRouteState, id: &str) -> Result<(), String> {
    let id = Uuid::parse_str(id).map_err(|error| error.to_string())?;
    let Some(local) = state
        .store
        .find_subscription(id)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(());
    };
    if local.status == crate::chargebee::ChargebeeSubscriptionStatus::Cancelled
        || super::cancel::pending_cancel(&local)
    {
        return Ok(());
    }
    let Some(provider_id) = local.chargebee_subscription_id.as_deref() else {
        return Ok(());
    };
    let provider = state
        .options
        .client
        .retrieve_subscription(provider_id)
        .await
        .map_err(|error| error.to_string())?;
    if !provider_reports_cancellation(&provider) || local.canceled_at.is_some() {
        return Ok(());
    }
    let status = crate::chargebee::ChargebeeSubscriptionStatus::from_str(&provider.status)
        .map_err(|error| error.to_string())?;
    let canceled_at = provider
        .cancelled_at
        .filter(|value| *value != 0)
        .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
        .unwrap_or_else(Utc::now);
    let updated = state
        .store
        .update_subscription(
            local.id,
            crate::chargebee::ChargebeeSubscriptionPatch {
                status: Some(status.clone()),
                canceled_at: Some(Some(canceled_at)),
                ..crate::chargebee::ChargebeeSubscriptionPatch::default()
            },
        )
        .await
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| {
            let mut updated = local.clone();
            updated.status = status;
            updated.canceled_at = Some(canceled_at);
            updated
        });
    if let Some(callbacks) = state
        .options
        .subscription
        .as_ref()
        .and_then(|options| options.callbacks.as_ref())
    {
        callbacks
            .on_subscription_cancel(&updated, &provider)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn provider_reports_cancellation(
    provider: &crate::chargebee::ChargebeeProviderSubscription,
) -> bool {
    provider.status == "cancelled" || provider.cancelled_at.is_some_and(|value| value != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn provider(
        status: &str,
        cancelled_at: Option<i64>,
    ) -> crate::chargebee::ChargebeeProviderSubscription {
        crate::chargebee::ChargebeeProviderSubscription {
            id: "provider".into(),
            customer_id: "customer".into(),
            status: status.into(),
            current_term_start: None,
            current_term_end: None,
            trial_start: None,
            trial_end: None,
            cancelled_at,
            subscription_items: Vec::new(),
            metadata: None,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn callback_requires_provider_evidence_before_mutation() {
        assert!(!provider_reports_cancellation(&provider("active", None)));
        assert!(!provider_reports_cancellation(&provider("active", Some(0))));
        assert!(provider_reports_cancellation(&provider("cancelled", None)));
        assert!(provider_reports_cancellation(&provider("active", Some(1))));
    }
}
