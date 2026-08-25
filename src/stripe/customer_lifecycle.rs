use super::{
    StripeCallbackContext, StripeCustomer, StripeMetadata, StripeOptions, StripeStore,
    StripeUserSnapshot, escape_search_value, merge_metadata,
};
use crate::{AuthUser, DatabaseHookContext};
use serde_json::{Map, Value, json};

pub(crate) fn callback_context(context: &DatabaseHookContext) -> Option<StripeCallbackContext> {
    let request = context.request.as_ref()?;
    Some(StripeCallbackContext {
        method: Some(request.method.clone()),
        path: Some(request.path.clone()),
        query: request.query.clone(),
        headers: request.headers.clone(),
    })
}

pub(crate) async fn after_user_create(
    options: &StripeOptions,
    store: &dyn StripeStore,
    user: &AuthUser,
    context: &DatabaseHookContext,
) {
    let Some(callback_context) = callback_context(context) else {
        return;
    };
    if !options.create_customer_on_sign_up {
        return;
    }
    let existing_id = match store.user_customer_id(user.id).await {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(message = %error, "Failed to create or link Stripe customer");
            return;
        }
    };
    if existing_id.is_some() {
        return;
    }
    if let Err(error) = create_or_link(options, store, user, &callback_context).await {
        tracing::error!(message = %error, "Failed to create or link Stripe customer");
    }
}

pub(crate) async fn after_user_update(
    options: &StripeOptions,
    store: &dyn StripeStore,
    user: &AuthUser,
    context: &DatabaseHookContext,
) {
    if callback_context(context).is_none() {
        return;
    }
    let customer_id = match store.user_customer_id(user.id).await {
        Ok(Some(id)) => id,
        Ok(None) => return,
        Err(error) => {
            tracing::error!(message = %error, "Failed to sync email to Stripe customer");
            return;
        }
    };
    let result = async {
        let customer = options.client.retrieve_customer(&customer_id).await?;
        if customer.deleted {
            tracing::warn!(%customer_id, "Stripe customer was deleted, cannot update email");
            return Ok::<(), super::StripeProviderError>(());
        }
        if customer.email.as_deref() != Some(user.email.as_str()) {
            options
                .client
                .update_customer(&customer_id, json!({ "email": user.email }))
                .await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        tracing::error!(message = %error, "Failed to sync email to Stripe customer");
    }
}

async fn create_or_link(
    options: &StripeOptions,
    store: &dyn StripeStore,
    user: &AuthUser,
    context: &StripeCallbackContext,
) -> Result<(), LifecycleError> {
    let mut customer = search_customer(options, &user.email).await;
    if let Some(found) = &customer {
        let owner = found.metadata.get("userId").and_then(Value::as_str);
        if owner.is_some_and(|owner| owner != user.id.to_string()) || !user.email_verified {
            customer = None;
        }
    }
    let linked = customer.is_some();
    let customer = match customer {
        Some(customer) => customer,
        None => create_customer(options, user, context).await?,
    };
    store
        .set_user_customer_id(user.id, Some(customer.id.clone()))
        .await?;
    if let Some(callback) = &options.on_customer_create {
        callback
            .call(
                &customer,
                &snapshot(user, Some(customer.id.clone())),
                context,
            )
            .await?;
    }
    if linked {
        tracing::info!(customer_id = %customer.id, user_id = %user.id, "Linked existing Stripe customer");
    } else {
        tracing::info!(customer_id = %customer.id, user_id = %user.id, "Created new Stripe customer");
    }
    Ok(())
}

async fn search_customer(options: &StripeOptions, email: &str) -> Option<StripeCustomer> {
    let query = format!(
        "email:\"{}\" AND -metadata[\"customerType\"]:\"organization\"",
        escape_search_value(email)
    );
    match options
        .client
        .search_customers(json!({ "query": query, "limit": 1 }))
        .await
    {
        Ok(page) => page.data.into_iter().next(),
        Err(_) => {
            tracing::warn!("Stripe customers.search failed, falling back to customers.list");
            list_customer(options, email).await
        }
    }
}

async fn list_customer(options: &StripeOptions, email: &str) -> Option<StripeCustomer> {
    let mut starting_after: Option<String> = None;
    loop {
        let mut params = json!({ "email": email, "limit": 100 });
        if let Some(cursor) = &starting_after {
            params["starting_after"] = Value::String(cursor.clone());
        }
        let page = options.client.list_customers(params).await.ok()?;
        if let Some(customer) = page.data.iter().find(|customer| {
            customer
                .metadata
                .get("customerType")
                .and_then(Value::as_str)
                != Some("organization")
        }) {
            return Some(customer.clone());
        }
        if !page.has_more {
            return None;
        }
        starting_after = page.data.last().map(|customer| customer.id.clone());
        starting_after.as_ref()?;
    }
}

async fn create_customer(
    options: &StripeOptions,
    user: &AuthUser,
    context: &StripeCallbackContext,
) -> Result<StripeCustomer, LifecycleError> {
    let extra = match &options.get_customer_create_params {
        Some(callback) => callback.params(&snapshot(user, None), context).await?,
        None => Value::Object(Map::new()),
    };
    let mut params = extra.as_object().cloned().unwrap_or_default();
    let extra_metadata = params
        .remove("metadata")
        .and_then(|metadata| serde_json::from_value::<StripeMetadata>(metadata).ok())
        .unwrap_or_default();
    let user_id = user.id.to_string();
    params.insert("email".into(), Value::String(user.email.clone()));
    params.insert("name".into(), Value::String(user.name.clone()));
    params.insert(
        "metadata".into(),
        serde_json::to_value(merge_metadata(
            [&extra_metadata],
            [("userId", user_id.as_str()), ("customerType", "user")],
        ))
        .expect("Stripe metadata serializes"),
    );
    options
        .client
        .create_customer(Value::Object(params))
        .await
        .map_err(Into::into)
}

fn snapshot(user: &AuthUser, stripe_customer_id: Option<String>) -> StripeUserSnapshot {
    StripeUserSnapshot {
        id: user.id.to_string(),
        name: user.name.clone(),
        email: user.email.clone(),
        email_verified: user.email_verified,
        stripe_customer_id,
        additional_fields: user.additional_fields.clone(),
    }
}

#[derive(Debug, thiserror::Error)]
enum LifecycleError {
    #[error(transparent)]
    Provider(#[from] super::StripeProviderError),
    #[error(transparent)]
    Store(#[from] super::StripeStoreError),
    #[error(transparent)]
    Callback(#[from] super::StripeCallbackError),
}
