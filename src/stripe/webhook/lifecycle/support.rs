use crate::stripe::{
    StripeCallbackContext, StripeCallbackError, StripeEvent, StripeMetadata, StripeOptions,
    StripeProviderError, StripeStore, StripeStoreError, SubscriptionConfiguration,
};
use serde_json::Value;

#[derive(Clone, Copy)]
pub(super) struct LifecycleContext<'a> {
    pub options: &'a StripeOptions,
    pub store: &'a dyn StripeStore,
}

impl LifecycleContext<'_> {
    pub fn subscriptions(&self) -> Option<&crate::stripe::SubscriptionOptions> {
        match &self.options.subscription {
            SubscriptionConfiguration::Disabled => None,
            SubscriptionConfiguration::Enabled(options) => Some(options),
        }
    }
}

pub(super) fn event_object<T: serde::de::DeserializeOwned>(
    event: &StripeEvent,
) -> Result<T, LifecycleError> {
    serde_json::from_value(event.data.object.clone()).map_err(LifecycleError::from)
}

pub(super) fn metadata_string<'a>(metadata: &'a StripeMetadata, key: &str) -> Option<&'a str> {
    metadata.get(key).and_then(Value::as_str)
}

pub(super) fn customer_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(values) => Some(
            values
                .iter()
                .map(|value| match value {
                    Value::Null => String::new(),
                    Value::String(value) => value.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(","),
        ),
        Value::Object(_) => Some("[object Object]".into()),
    }
}

pub(super) fn webhook_context() -> StripeCallbackContext {
    StripeCallbackContext {
        method: Some("POST".into()),
        path: Some("/stripe/webhook".into()),
        query: None,
        headers: Default::default(),
    }
}

#[derive(Debug, thiserror::Error)]
pub(in crate::stripe::webhook) enum LifecycleError {
    #[error("{0}")]
    Provider(#[from] StripeProviderError),
    #[error("{0}")]
    Store(#[from] StripeStoreError),
    #[error("{0}")]
    Callback(#[from] StripeCallbackError),
    #[error("invalid Stripe webhook object: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

impl LifecycleError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}
