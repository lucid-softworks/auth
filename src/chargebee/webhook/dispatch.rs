use super::{ChargebeeWebhookProcessingError, lifecycle};
use crate::chargebee::{ChargebeeOptions, ChargebeeStore, ChargebeeWebhookEvent};

pub(super) async fn built_in(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    event: &ChargebeeWebhookEvent,
) -> Result<(), ChargebeeWebhookProcessingError> {
    match event.event_type.as_str() {
        "subscription_created" => {
            if let (Some(subscription), Some(customer)) = (event.subscription(), event.customer()) {
                lifecycle::created::handle(options, store, subscription, customer).await;
            }
        }
        "subscription_activated" | "subscription_started" => {
            if let (Some(subscription), Some(customer)) = (event.subscription(), event.customer()) {
                lifecycle::complete::handle(options, store, subscription, customer).await;
            }
        }
        "subscription_changed"
        | "subscription_renewed"
        | "subscription_scheduled_cancellation_removed" => {
            if let (Some(subscription), Some(customer)) = (event.subscription(), event.customer()) {
                lifecycle::updated::handle(options, store, subscription, customer).await;
            }
        }
        "subscription_cancelled" => {
            if let Some(subscription) = event.subscription() {
                lifecycle::deleted::handle(options, store, subscription).await;
            }
        }
        "customer_deleted" => {
            lifecycle::customer::handle(options, store, event.customer())
                .await
                .map_err(|source| ChargebeeWebhookProcessingError::CustomerDeleted { source })?;
        }
        _ => tracing::info!(
            event_type = %event.event_type,
            "Unhandled Chargebee webhook event"
        ),
    }
    Ok(())
}
