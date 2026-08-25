use crate::{
    AuthError, Organization, OrganizationError, OrganizationErrorStatus, StripeErrorCode,
    StripePlugin, StripeProviderError, StripeStoreError, SubscriptionStatus,
};
use serde_json::{Value, json};

pub(super) async fn guard(
    plugin: &StripePlugin,
    organization: &Organization,
) -> Result<(), AuthError> {
    let customer_id = plugin
        .store
        .organization_customer_id(organization.id)
        .await
        .map_err(store_error)?;
    let Some(customer_id) = customer_id else {
        return Ok(());
    };

    let result = ensure_no_active_subscriptions(plugin, &customer_id).await;
    match result {
        Ok(()) => Ok(()),
        Err(DeletionGuardError::ActiveSubscription) => Err(OrganizationError::new(
            OrganizationErrorStatus::BadRequest,
            StripeErrorCode::OrganizationHasActiveSubscription.as_str(),
            StripeErrorCode::OrganizationHasActiveSubscription.message(),
        )
        .into()),
        Err(DeletionGuardError::Provider(error)) => {
            tracing::error!("Failed to check organization subscriptions: {error}");
            Err(AuthError::InvalidRequest(error.to_string()))
        }
    }
}

async fn ensure_no_active_subscriptions(
    plugin: &StripePlugin,
    customer_id: &str,
) -> Result<(), DeletionGuardError> {
    let mut starting_after: Option<String> = None;
    loop {
        let mut params = json!({
            "customer": customer_id,
            "status": "all",
            "limit": 100
        });
        if let Some(cursor) = &starting_after {
            params["starting_after"] = Value::String(cursor.clone());
        }
        let page = plugin.options.client.list_subscriptions(params).await?;
        if page.data.iter().any(|subscription| {
            !matches!(
                subscription.status,
                SubscriptionStatus::Canceled
                    | SubscriptionStatus::Incomplete
                    | SubscriptionStatus::IncompleteExpired
            )
        }) {
            return Err(DeletionGuardError::ActiveSubscription);
        }
        if !page.has_more {
            return Ok(());
        }
        starting_after = page.data.last().map(|subscription| subscription.id.clone());
        if starting_after.is_none() {
            return Ok(());
        }
    }
}

fn store_error(error: StripeStoreError) -> AuthError {
    AuthError::InvalidRequest(error.to_string())
}

#[derive(Debug, thiserror::Error)]
enum DeletionGuardError {
    #[error("organization has an active Stripe subscription")]
    ActiveSubscription,
    #[error(transparent)]
    Provider(#[from] StripeProviderError),
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        TestStripeClient, organization, plugin, provider_subscription,
    };
    use crate::{AuthError, MemoryStripeStore, StripeStore, SubscriptionStatus};
    use std::sync::Arc;

    #[tokio::test]
    async fn uses_the_exact_better_auth_error_for_blocking_statuses() {
        let client = Arc::new(TestStripeClient::new());
        client
            .subscriptions
            .lock()
            .unwrap()
            .push(provider_subscription(SubscriptionStatus::PastDue));
        let store = Arc::new(MemoryStripeStore::new());
        let organization = organization();
        store
            .set_organization_customer_id(organization.id, Some("cus_org".into()))
            .await
            .unwrap();
        let error = plugin(client, store, false)
            .before_organization_delete(&organization)
            .await
            .unwrap_err();
        let AuthError::Organization(error) = error else {
            panic!("expected organization API error");
        };
        assert_eq!(error.code, "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION");
        assert_eq!(
            error.message,
            "Cannot delete organization with active subscription"
        );
    }
}
