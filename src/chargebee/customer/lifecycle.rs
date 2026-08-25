use super::{hook_context, merge_object_spread, user_snapshot};
use crate::{AuthUser, DatabaseHookContext};
use serde_json::{Map, Value, json};

use crate::chargebee::{ChargebeeCustomerListRequest, ChargebeeOptions, ChargebeeStore};

pub(crate) async fn after_user_create(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    user: &AuthUser,
) {
    if options.organization_enabled() || !options.create_customer_on_sign_up {
        return;
    }
    let snapshot = user_snapshot(store, user).await;
    let existing = match options
        .client
        .list_customers(ChargebeeCustomerListRequest {
            email: Some(user.email.clone()),
            limit: Some(1),
        })
        .await
    {
        Ok(existing) => existing,
        Err(error) => {
            tracing::error!(user_id = %user.id, %error, "Error creating Chargebee customer for user");
            return;
        }
    };
    let customer = if let Some(customer) = existing.into_iter().next() {
        customer
    } else {
        let mut request = Map::from_iter([
            ("email".into(), Value::String(user.email.clone())),
            (
                "meta_data".into(),
                json!({"userId": user.id, "customerType": "user"}),
            ),
        ]);
        if let Some(provider) = &options.get_customer_create_params {
            match provider.params(&snapshot, None).await {
                Ok(extra) => merge_object_spread(&mut request, extra),
                Err(error) => {
                    tracing::error!(user_id = %user.id, %error, "Error creating Chargebee customer for user");
                    return;
                }
            }
        }
        match options.client.create_customer(Value::Object(request)).await {
            Ok(customer) => customer,
            Err(error) => {
                tracing::error!(user_id = %user.id, %error, "Error creating Chargebee customer for user");
                return;
            }
        }
    };
    if let Err(error) = store
        .set_user_customer_id(user.id, Some(customer.id.clone()))
        .await
    {
        tracing::error!(user_id = %user.id, %error, "Error persisting Chargebee customer for user");
        return;
    }
    if let Some(callback) = &options.on_customer_create
        && let Err(error) = callback.call(&customer, &snapshot).await
    {
        tracing::error!(user_id = %user.id, %error, "Error creating Chargebee customer for user");
    }
}

pub(crate) async fn after_user_update(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    user: &AuthUser,
) {
    if options.organization_enabled() {
        return;
    }
    let Ok(Some(customer_id)) = store.user_customer_id(user.id).await else {
        return;
    };
    let _ = options
        .client
        .update_customer(&customer_id, json!({"email": user.email}))
        .await;
}

pub(crate) async fn before_user_delete(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    user: &AuthUser,
    context: &DatabaseHookContext,
) {
    let result = async {
        let subscriptions = store
            .list_subscriptions_by_reference(&user.id.to_string())
            .await?;
        for subscription in &subscriptions {
            if let Some(provider_id) = &subscription.chargebee_subscription_id
                && let Err(error) = options.client.cancel_subscription(provider_id, false).await
            {
                tracing::warn!(%error, "Failed to cancel subscription in Chargebee");
            }
            store.delete_subscription_items(subscription.id).await?;
            store.delete_subscription(subscription.id).await?;
        }
        Ok::<_, super::super::ChargebeeStoreError>(subscriptions.len())
    }
    .await;
    match result {
        Ok(count) => {
            tracing::info!(user_id = %user.id, count, "Cleaned up Chargebee subscriptions for user")
        }
        Err(error) => {
            let request = hook_context(context);
            tracing::error!(user_id = %user.id, path = ?request.path, %error, "Error cleaning up Chargebee subscriptions for user");
        }
    }
}
