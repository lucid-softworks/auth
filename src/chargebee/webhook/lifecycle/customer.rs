use super::mapping;
use crate::chargebee::{
    ChargebeeOptions, ChargebeeProviderCustomer, ChargebeeStore, ChargebeeStoreError,
};
use uuid::Uuid;

pub(in crate::chargebee::webhook) async fn handle(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    customer: Option<ChargebeeProviderCustomer>,
) -> Result<(), ChargebeeStoreError> {
    let Some(customer) = customer else {
        tracing::warn!("Missing customer in deletion event");
        return Ok(());
    };

    let subscriptions = store.list_subscriptions_by_customer(&customer.id).await?;
    for subscription in subscriptions {
        store.delete_subscription_items(subscription.id).await?;
        store.delete_subscription(subscription.id).await?;
    }

    clear_from_metadata(store, &customer).await?;
    clear_fallback(options, store, &customer.id).await;
    tracing::info!(
        customer_id = %customer.id,
        "Customer and associated Chargebee data deleted successfully"
    );
    Ok(())
}

async fn clear_from_metadata(
    store: &dyn ChargebeeStore,
    customer: &ChargebeeProviderCustomer,
) -> Result<(), ChargebeeStoreError> {
    match mapping::metadata_string(customer.metadata.as_ref(), "customerType") {
        Some("organization") => {
            if let Some(id) = mapping::metadata_string(customer.metadata.as_ref(), "organizationId")
                .and_then(|id| Uuid::parse_str(id).ok())
            {
                store.set_organization_customer_id(id, None).await?;
                tracing::info!(organization_id = %id, "Cleared chargebeeCustomerId");
            }
        }
        Some("user") => {
            if let Some(id) = mapping::metadata_string(customer.metadata.as_ref(), "userId")
                .and_then(|id| Uuid::parse_str(id).ok())
            {
                store.set_user_customer_id(id, None).await?;
                tracing::info!(user_id = %id, "Cleared chargebeeCustomerId");
            }
        }
        _ => {}
    }
    Ok(())
}

async fn clear_fallback(options: &ChargebeeOptions, store: &dyn ChargebeeStore, customer_id: &str) {
    if options.organization_enabled() {
        let result = async {
            if let Some(id) = store.organization_id_by_customer(customer_id).await? {
                store.set_organization_customer_id(id, None).await?;
            }
            Ok::<_, ChargebeeStoreError>(())
        }
        .await;
        if let Err(error) = result {
            tracing::error!(message = %error, "Error clearing chargebeeCustomerId from organizations");
        }
    } else {
        let result = async {
            if let Some(id) = store.user_id_by_customer(customer_id).await? {
                store.set_user_customer_id(id, None).await?;
            }
            Ok::<_, ChargebeeStoreError>(())
        }
        .await;
        if let Err(error) = result {
            tracing::error!(message = %error, "Error clearing chargebeeCustomerId from users");
        }
    }
}
