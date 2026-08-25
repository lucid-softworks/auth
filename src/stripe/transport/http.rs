use super::{
    StripeBillingPortalSession, StripeCheckoutSession, StripeClient, StripeCustomer, StripeEvent,
    StripePage, StripePrice, StripeProviderError, StripeRequestOptions, StripeSubscription,
    StripeSubscriptionSchedule, signature,
};
use async_trait::async_trait;
use reqwest::{Method, Response};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{fmt, sync::Arc};
use url::Url;

#[derive(Clone)]
pub struct StripeHttpClient {
    http: reqwest::Client,
    api_key: Arc<str>,
    api_base: Url,
    api_version: Option<Arc<str>>,
}

impl StripeHttpClient {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: Arc::from(api_key.into()),
            api_base: Url::parse("https://api.stripe.com/v1/").expect("Stripe API URL is valid"),
            api_version: None,
        }
    }

    pub fn with_api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(Arc::from(version.into()));
        self
    }

    /// Override intended for deterministic contract fixtures and private proxies.
    pub fn with_api_base(mut self, api_base: Url) -> Self {
        self.api_base = api_base;
        self
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        params: Value,
    ) -> Result<T, StripeProviderError> {
        self.request(Method::GET, path, params, None).await
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        params: Value,
        options: Option<StripeRequestOptions>,
    ) -> Result<T, StripeProviderError> {
        self.request(Method::POST, path, params, options).await
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        params: Value,
        options: Option<StripeRequestOptions>,
    ) -> Result<T, StripeProviderError> {
        let url = self
            .api_base
            .join(path)
            .map_err(|error| StripeProviderError::transport(error.to_string()))?;
        let encoded = encode_form(&params);
        let mut request = self
            .http
            .request(method.clone(), url)
            .bearer_auth(self.api_key.as_ref());
        let version = options
            .as_ref()
            .and_then(|options| options.api_version.as_deref())
            .or(self.api_version.as_deref());
        if let Some(version) = version {
            request = request.header("Stripe-Version", version);
        }
        if let Some(options) = options {
            if let Some(key) = options.idempotency_key {
                request = request.header("Idempotency-Key", key);
            }
            if let Some(account) = options.stripe_account {
                request = request.header("Stripe-Account", account);
            }
        }
        request = if method == Method::GET {
            request.query(&encoded)
        } else {
            request
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(form_body(&encoded))
        };
        decode_response(request.send().await.map_err(transport_error)?).await
    }
}

impl fmt::Debug for StripeHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StripeHttpClient")
            .field("api_key", &"[REDACTED]")
            .field("api_base", &self.api_base)
            .field("api_version", &self.api_version)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl StripeClient for StripeHttpClient {
    async fn create_customer(&self, params: Value) -> Result<StripeCustomer, StripeProviderError> {
        self.post("customers", params, None).await
    }

    async fn search_customers(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeCustomer>, StripeProviderError> {
        self.get("customers/search", params).await
    }

    async fn list_customers(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeCustomer>, StripeProviderError> {
        self.get("customers", params).await
    }

    async fn retrieve_customer(&self, id: &str) -> Result<StripeCustomer, StripeProviderError> {
        self.get(&format!("customers/{}", path_segment(id)), Value::Null)
            .await
    }

    async fn update_customer(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeCustomer, StripeProviderError> {
        self.post(&format!("customers/{}", path_segment(id)), params, None)
            .await
    }

    async fn list_prices(
        &self,
        params: Value,
    ) -> Result<StripePage<StripePrice>, StripeProviderError> {
        self.get("prices", params).await
    }

    async fn retrieve_price(&self, id: &str) -> Result<StripePrice, StripeProviderError> {
        self.get(&format!("prices/{}", path_segment(id)), Value::Null)
            .await
    }

    async fn create_checkout_session(
        &self,
        params: Value,
        options: Option<StripeRequestOptions>,
    ) -> Result<StripeCheckoutSession, StripeProviderError> {
        self.post("checkout/sessions", params, options).await
    }

    async fn retrieve_checkout_session(
        &self,
        id: &str,
    ) -> Result<StripeCheckoutSession, StripeProviderError> {
        self.get(
            &format!("checkout/sessions/{}", path_segment(id)),
            Value::Null,
        )
        .await
    }

    async fn list_subscriptions(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeSubscription>, StripeProviderError> {
        self.get("subscriptions", params).await
    }

    async fn retrieve_subscription(
        &self,
        id: &str,
    ) -> Result<StripeSubscription, StripeProviderError> {
        self.get(&format!("subscriptions/{}", path_segment(id)), Value::Null)
            .await
    }

    async fn update_subscription(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeSubscription, StripeProviderError> {
        self.post(&format!("subscriptions/{}", path_segment(id)), params, None)
            .await
    }

    async fn list_subscription_schedules(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeSubscriptionSchedule>, StripeProviderError> {
        self.get("subscription_schedules", params).await
    }

    async fn create_subscription_schedule(
        &self,
        params: Value,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        self.post("subscription_schedules", params, None).await
    }

    async fn retrieve_subscription_schedule(
        &self,
        id: &str,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        self.get(
            &format!("subscription_schedules/{}", path_segment(id)),
            Value::Null,
        )
        .await
    }

    async fn update_subscription_schedule(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        self.post(
            &format!("subscription_schedules/{}", path_segment(id)),
            params,
            None,
        )
        .await
    }

    async fn release_subscription_schedule(
        &self,
        id: &str,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        self.post(
            &format!("subscription_schedules/{}/release", path_segment(id)),
            Value::Null,
            None,
        )
        .await
    }

    async fn create_billing_portal_session(
        &self,
        params: Value,
    ) -> Result<StripeBillingPortalSession, StripeProviderError> {
        self.post("billing_portal/sessions", params, None).await
    }

    async fn construct_webhook_event(
        &self,
        payload: &[u8],
        signature: &str,
        secret: &str,
    ) -> Result<StripeEvent, StripeProviderError> {
        signature::construct_event(payload, signature, secret)
    }
}

async fn decode_response<T: DeserializeOwned>(
    response: Response,
) -> Result<T, StripeProviderError> {
    let status = response.status();
    let bytes = response.bytes().await.map_err(transport_error)?;
    if status.is_success() {
        return serde_json::from_slice(&bytes)
            .map_err(|error| StripeProviderError::transport(error.to_string()));
    }
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let error = value.get("error").unwrap_or(&value);
    Err(StripeProviderError {
        code: error.get("code").and_then(Value::as_str).map(str::to_owned),
        message: error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Stripe request failed")
            .to_owned(),
        status: Some(status.as_u16()),
    })
}

fn transport_error(error: reqwest::Error) -> StripeProviderError {
    StripeProviderError::transport(error.to_string())
}

fn encode_form(value: &Value) -> Vec<(String, String)> {
    let mut output = Vec::new();
    flatten_value(None, value, &mut output);
    output
}

fn flatten_value(prefix: Option<String>, value: &Value, output: &mut Vec<(String, String)>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let key = prefix
                    .as_ref()
                    .map_or_else(|| key.clone(), |prefix| format!("{prefix}[{key}]"));
                flatten_value(Some(key), value, output);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let key = prefix
                    .as_ref()
                    .map(|prefix| format!("{prefix}[{index}]"))
                    .unwrap_or_else(|| index.to_string());
                flatten_value(Some(key), value, output);
            }
        }
        Value::Null => {
            if let Some(key) = prefix {
                output.push((key, String::new()));
            }
        }
        Value::Bool(value) => push_scalar(prefix, value.to_string(), output),
        Value::Number(value) => push_scalar(prefix, value.to_string(), output),
        Value::String(value) => push_scalar(prefix, value.clone(), output),
    }
}

fn push_scalar(prefix: Option<String>, value: String, output: &mut Vec<(String, String)>) {
    if let Some(key) = prefix {
        output.push((key, value));
    }
}

fn path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn form_body(fields: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in fields {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stripe_form_encoding_preserves_nested_arrays_and_empty_clears() {
        assert_eq!(
            encode_form(&json!({
                "items": [{ "id": "si_1", "quantity": 3 }],
                "cancel_at": "",
                "metadata": { "attempt": 2 }
            })),
            vec![
                ("items[0][id]".into(), "si_1".into()),
                ("items[0][quantity]".into(), "3".into()),
                ("cancel_at".into(), "".into()),
                ("metadata[attempt]".into(), "2".into()),
            ]
        );
    }

    #[test]
    fn debug_never_exposes_the_api_key() {
        let debug = format!("{:?}", StripeHttpClient::new("sk_live_secret"));
        assert!(!debug.contains("sk_live_secret"));
        assert!(debug.contains("[REDACTED]"));
    }
}
