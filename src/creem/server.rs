use super::{
    CreemCheckoutCustomer, CreemCheckoutRequest, CreemCustomField, CreemHttpTransport,
    CreemPortalRequest, CreemProviderConfig, CreemProviderError, CreemProviderSubscription,
    CreemStore, CreemSubscription, CreemTransactionPage, CreemTransactionSearch, CreemTransport,
    validate_creem_webhook_signature,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{fmt, sync::Arc};

const SERVER_API_KEY_ERROR: &str =
    "Creem API key is not configured. Please provide an apiKey in the CreemServerConfig.";

#[derive(Clone)]
pub struct CreemServerConfig {
    pub api_key: String,
    pub test_mode: bool,
    transport: Option<Arc<dyn CreemTransport>>,
}

impl CreemServerConfig {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            test_mode: false,
            transport: None,
        }
    }

    pub fn with_transport(api_key: impl Into<String>, transport: Arc<dyn CreemTransport>) -> Self {
        Self {
            api_key: api_key.into(),
            test_mode: false,
            transport: Some(transport),
        }
    }
}

impl fmt::Debug for CreemServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreemServerConfig")
            .field("api_key", &"[REDACTED]")
            .field("test_mode", &self.test_mode)
            .field("custom_transport", &self.transport.is_some())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct CreemServerCheckoutInput {
    pub product_id: String,
    pub request_id: Option<String>,
    pub units: Option<f64>,
    pub discount_code: Option<String>,
    pub customer: CreemCheckoutCustomer,
    pub custom_fields: Option<Vec<CreemCustomField>>,
    pub custom_field: Option<Vec<CreemCustomField>>,
    pub success_url: Option<String>,
    pub metadata: Option<Map<String, Value>>,
    pub skip_trial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreemRedirect {
    pub url: String,
    pub redirect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreemCancellation {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreemServerAccess {
    pub has_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreemActiveSubscription {
    pub id: Option<String>,
    pub status: String,
    pub product_id: String,
    pub period_end: Option<DateTime<Utc>>,
}

pub fn create_creem_client(config: &CreemServerConfig) -> Arc<dyn CreemTransport> {
    config.transport.clone().unwrap_or_else(|| {
        let provider = if config.test_mode {
            CreemProviderConfig::test(config.api_key.clone())
        } else {
            CreemProviderConfig::production(config.api_key.clone())
        };
        Arc::new(CreemHttpTransport::new(provider))
    })
}

pub async fn create_creem_checkout(
    config: &CreemServerConfig,
    input: CreemServerCheckoutInput,
) -> Result<CreemRedirect, CreemProviderError> {
    require_api_key(config)?;
    let mut metadata = input.metadata.unwrap_or_default();
    if input.skip_trial {
        metadata.insert("skipTrial".into(), Value::Bool(true));
    }
    let checkout = create_creem_client(config)
        .create_checkout(CreemCheckoutRequest {
            request_id: input.request_id,
            product_id: input.product_id,
            units: input.units,
            discount_code: input.discount_code,
            customer: Some(input.customer),
            custom_fields: input.custom_fields.or(input.custom_field),
            success_url: input.success_url,
            metadata: Some(metadata),
        })
        .await?;
    let url = checkout
        .checkout_url
        .ok_or_else(|| CreemProviderError::new("Creem API returned no checkout URL"))?;
    Ok(CreemRedirect {
        url,
        redirect: true,
    })
}

pub async fn create_creem_portal(
    config: &CreemServerConfig,
    customer_id: impl Into<String>,
) -> Result<CreemRedirect, CreemProviderError> {
    require_api_key(config)?;
    let portal = create_creem_client(config)
        .create_portal(CreemPortalRequest {
            customer_id: customer_id.into(),
        })
        .await?;
    Ok(CreemRedirect {
        url: portal.customer_portal_link,
        redirect: true,
    })
}

pub async fn cancel_creem_subscription(
    config: &CreemServerConfig,
    subscription_id: &str,
) -> Result<CreemCancellation, CreemProviderError> {
    require_api_key(config)?;
    create_creem_client(config)
        .cancel_subscription(subscription_id)
        .await?;
    Ok(CreemCancellation {
        success: true,
        message: "Subscription cancelled successfully".into(),
    })
}

pub async fn retrieve_creem_subscription(
    config: &CreemServerConfig,
    subscription_id: &str,
) -> Result<CreemProviderSubscription, CreemProviderError> {
    require_api_key(config)?;
    create_creem_client(config)
        .retrieve_subscription(subscription_id)
        .await
}

pub async fn search_creem_transactions(
    config: &CreemServerConfig,
    filters: CreemTransactionSearch,
) -> Result<CreemTransactionPage, CreemProviderError> {
    require_api_key(config)?;
    create_creem_client(config)
        .search_transactions(filters)
        .await
}

pub fn is_active_creem_subscription(status: &str) -> bool {
    matches!(
        status.to_ascii_lowercase().as_str(),
        "active" | "trialing" | "paid"
    )
}

pub fn format_creem_date(timestamp_seconds: f64) -> Option<DateTime<Utc>> {
    if !timestamp_seconds.is_finite() {
        return None;
    }
    let milliseconds = timestamp_seconds * 1_000.0;
    if !(-8_640_000_000_000_000.0..=8_640_000_000_000_000.0).contains(&milliseconds) {
        return None;
    }
    DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
}

pub fn get_creem_days_until_renewal(period_end_timestamp: f64) -> Option<i64> {
    let renewal = format_creem_date(period_end_timestamp)?;
    let milliseconds = renewal.timestamp_millis() - Utc::now().timestamp_millis();
    Some((milliseconds as f64 / 86_400_000.0).ceil() as i64)
}

pub fn validate_creem_server_webhook_signature(
    payload: &str,
    signature: Option<&str>,
    secret: &str,
) -> bool {
    validate_creem_webhook_signature(payload, signature, secret)
}

pub async fn check_creem_subscription_access(
    _config: &CreemServerConfig,
    store: Option<&dyn CreemStore>,
    user_id: Option<&str>,
    _customer_id: Option<&str>,
) -> CreemServerAccess {
    let Some((store, user_id)) = store.zip(user_id) else {
        return no_access();
    };
    let subscriptions = match store.list_subscriptions_by_reference(user_id).await {
        Ok(subscriptions) => subscriptions,
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to check subscription access (database mode)");
            return no_access();
        }
    };
    subscriptions
        .into_iter()
        .find(|subscription| matches!(subscription.status.as_str(), "active" | "trialing" | "paid"))
        .map(|subscription| CreemServerAccess {
            has_access: true,
            status: Some(subscription.status),
            subscription_id: subscription.creem_subscription_id,
            expires_at: subscription.period_end,
        })
        .unwrap_or_else(no_access)
}

pub async fn get_active_creem_subscriptions(
    _config: &CreemServerConfig,
    store: Option<&dyn CreemStore>,
    user_id: Option<&str>,
    _customer_id: Option<&str>,
) -> Vec<CreemActiveSubscription> {
    let Some((store, user_id)) = store.zip(user_id) else {
        return Vec::new();
    };
    match store.list_subscriptions_by_reference(user_id).await {
        Ok(subscriptions) => subscriptions
            .into_iter()
            .filter(active_database_subscription)
            .map(|subscription| CreemActiveSubscription {
                id: subscription.creem_subscription_id,
                status: subscription.status,
                product_id: subscription.product_id,
                period_end: subscription.period_end,
            })
            .collect(),
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to get active subscriptions (database mode)");
            Vec::new()
        }
    }
}

fn active_database_subscription(subscription: &CreemSubscription) -> bool {
    matches!(subscription.status.as_str(), "active" | "trialing" | "paid")
}

fn no_access() -> CreemServerAccess {
    CreemServerAccess {
        has_access: false,
        status: None,
        subscription_id: None,
        expires_at: None,
    }
}

fn require_api_key(config: &CreemServerConfig) -> Result<(), CreemProviderError> {
    if config.api_key.is_empty() {
        Err(CreemProviderError::new(SERVER_API_KEY_ERROR))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_helpers_match_case_and_timestamp_rules() {
        assert!(is_active_creem_subscription("PAID"));
        assert!(!is_active_creem_subscription("canceled"));
        assert_eq!(format_creem_date(1.25).unwrap().timestamp_millis(), 1_250);
        assert!(format_creem_date(f64::NAN).is_none());
    }

    #[tokio::test]
    async fn only_provider_helpers_require_an_api_key() {
        let config = CreemServerConfig::new("");
        let error = create_creem_portal(&config, "customer").await.unwrap_err();
        assert_eq!(error.message, SERVER_API_KEY_ERROR);
        assert!(
            !check_creem_subscription_access(&config, None, None, None)
                .await
                .has_access
        );
        assert!(
            get_active_creem_subscriptions(&config, None, None, None)
                .await
                .is_empty()
        );
    }
}
