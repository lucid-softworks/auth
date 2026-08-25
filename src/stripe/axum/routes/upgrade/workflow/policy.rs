use crate::{
    AuthService, CustomerType, StripeError, StripeErrorCode, StripeOrganizationSnapshot,
    StripePlan, StripePlugin, StripePrice, StripeSubscriptionItem, Subscription,
    SubscriptionStatus,
};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

pub(super) async fn organization_context(
    service: &AuthService,
    reference_id: &str,
    customer_type: CustomerType,
    customer_needed: bool,
    member_count_needed: bool,
) -> Result<(Option<StripeOrganizationSnapshot>, f64), StripeError> {
    if customer_type != CustomerType::Organization || (!customer_needed && !member_count_needed) {
        return Ok((None, 0.0));
    }
    let id = Uuid::parse_str(reference_id)
        .map_err(|_| known(400, StripeErrorCode::OrganizationNotFound))?;
    let plugin = service
        .organization_plugin()
        .map_err(|_| known(400, StripeErrorCode::OrganizationNotFound))?;
    let organization = if customer_needed {
        let organization = plugin
            .store
            .find_organization_by_id(id)
            .await
            .map_err(auth_error)?
            .ok_or_else(|| known(400, StripeErrorCode::OrganizationNotFound))?;
        Some(StripeOrganizationSnapshot {
            id: organization.id.to_string(),
            name: organization.name,
            stripe_customer_id: None,
            metadata: organization.metadata,
        })
    } else {
        None
    };
    let member_count = if member_count_needed {
        plugin
            .store
            .list_members(id)
            .await
            .map_err(auth_error)?
            .len() as f64
    } else {
        0.0
    };
    Ok((organization, member_count))
}

pub(super) async fn resolve_price(
    plugin: &StripePlugin,
    price_id: Option<&str>,
    lookup_key: Option<&str>,
) -> Option<StripePrice> {
    if let Some(lookup_key) = lookup_key {
        let page = match plugin
            .options
            .client
            .list_prices(json!({
                "lookup_keys": [lookup_key],
                "active": true,
                "limit": 1,
            }))
            .await
        {
            Ok(page) => page,
            Err(_) => return None,
        };
        if let Some(price) = page.data.into_iter().next() {
            return Some(price);
        }
    }
    match price_id {
        Some(price_id) => plugin.options.client.retrieve_price(price_id).await.ok(),
        None => None,
    }
}

pub(super) async fn resolve_plan_item(
    plugin: &StripePlugin,
    items: &[StripeSubscriptionItem],
) -> Result<Option<(StripeSubscriptionItem, Option<StripePlan>)>, StripeError> {
    let Some(first) = items.first() else {
        return Ok(None);
    };
    let plans = plugin.options.plans().await.map_err(callback_error)?;
    for item in items {
        let plan = plans.iter().find(|plan| {
            plan.price_id.as_deref() == Some(item.price.id.as_str())
                || plan.annual_discount_price_id.as_deref() == Some(item.price.id.as_str())
                || item.price.lookup_key.as_ref().is_some_and(|lookup| {
                    plan.lookup_key.as_ref() == Some(lookup)
                        || plan.annual_discount_lookup_key.as_ref() == Some(lookup)
                })
        });
        if let Some(plan) = plan {
            return Ok(Some((item.clone(), Some(plan.clone()))));
        }
    }
    Ok((items.len() == 1).then(|| (first.clone(), None)))
}

pub(super) fn reject_duplicate(
    subscription: Option<&Subscription>,
    requested_plan: &str,
    requested_seats: Option<f64>,
    automatic_seats: bool,
    stripe_price_id: Option<&str>,
    requested_price_id: &str,
) -> Result<(), StripeError> {
    let Some(subscription) = subscription else {
        return Ok(());
    };
    let same_seats = automatic_seats
        || subscription.seats == Some(super::super::checkout::js_or_one(requested_seats));
    let still_valid = subscription
        .period_end
        .is_none_or(|period_end| period_end > Utc::now());
    if subscription.status == SubscriptionStatus::Active
        && subscription.plan == requested_plan
        && same_seats
        && stripe_price_id == Some(requested_price_id)
        && still_valid
    {
        return Err(known(400, StripeErrorCode::AlreadySubscribedPlan));
    }
    Ok(())
}

pub(super) fn known(status: u16, code: StripeErrorCode) -> StripeError {
    StripeError::from_code(status, code)
}

pub(super) fn raw_bad_request(message: impl Into<String>) -> StripeError {
    StripeError {
        status: 400,
        code: "BAD_REQUEST".into(),
        message: message.into(),
    }
}

pub(super) fn provider_error(error: crate::StripeProviderError) -> StripeError {
    StripeError::provider_bad_request(error.code.as_deref(), error.message)
}

pub(super) fn uncaught_provider_error(error: crate::StripeProviderError) -> StripeError {
    tracing::error!(message = %error, "Stripe provider request failed");
    internal_error("Authentication failed")
}

pub(super) fn store_error(error: crate::StripeStoreError) -> StripeError {
    tracing::error!(message = %error, "Stripe persistence failed");
    internal_error("Authentication failed")
}

pub(super) fn callback_error(error: crate::StripeCallbackError) -> StripeError {
    internal_error(error.message)
}

pub(super) fn auth_error(error: crate::AuthError) -> StripeError {
    tracing::error!(message = %error, "Stripe upgrade dependency failed");
    internal_error("Authentication failed")
}

fn internal_error(message: impl Into<String>) -> StripeError {
    StripeError {
        status: 500,
        code: "INTERNAL_SERVER_ERROR".into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn duplicate_guard_is_case_sensitive_and_checks_expiry() {
        let mut subscription = stored_subscription();
        assert!(
            reject_duplicate(
                Some(&subscription),
                "pro",
                Some(1.0),
                false,
                Some("price"),
                "price"
            )
            .is_err()
        );
        assert!(
            reject_duplicate(
                Some(&subscription),
                "PRO",
                Some(1.0),
                false,
                Some("price"),
                "price"
            )
            .is_ok()
        );
        subscription.period_end = Some(Utc::now() - Duration::seconds(1));
        assert!(
            reject_duplicate(
                Some(&subscription),
                "pro",
                Some(1.0),
                false,
                Some("price"),
                "price"
            )
            .is_ok()
        );
    }

    fn stored_subscription() -> Subscription {
        let now = Utc::now();
        Subscription {
            id: Uuid::new_v4(),
            plan: "pro".into(),
            reference_id: "ref".into(),
            stripe_customer_id: Some("customer".into()),
            stripe_subscription_id: Some("stripe".into()),
            status: SubscriptionStatus::Active,
            period_start: None,
            period_end: Some(now + Duration::days(1)),
            trial_start: None,
            trial_end: None,
            cancel_at_period_end: false,
            cancel_at: None,
            canceled_at: None,
            ended_at: None,
            seats: Some(1.0),
            billing_interval: None,
            stripe_schedule_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}
