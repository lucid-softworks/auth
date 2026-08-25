use super::{DodoCustomerParamsProvider, DodoPaymentsClient, DodoProducts, DodoWebhookCallbacks};
use std::{fmt, sync::Arc};

#[derive(Clone)]
pub struct DodoPaymentsOptions {
    pub client: Arc<dyn DodoPaymentsClient>,
    pub create_customer_on_sign_up: bool,
    pub get_customer_params: Option<Arc<dyn DodoCustomerParamsProvider>>,
    pub features: Vec<DodoPaymentsFeature>,
}

impl DodoPaymentsOptions {
    pub fn new(client: Arc<dyn DodoPaymentsClient>, features: Vec<DodoPaymentsFeature>) -> Self {
        Self {
            client,
            create_customer_on_sign_up: false,
            get_customer_params: None,
            features,
        }
    }

    pub fn checkout(&self) -> Option<&DodoCheckoutOptions> {
        checkout_feature(&self.features)
    }

    pub fn portal_enabled(&self) -> bool {
        self.features
            .iter()
            .any(|feature| matches!(feature, DodoPaymentsFeature::Portal))
    }

    pub fn usage_enabled(&self) -> bool {
        self.features
            .iter()
            .any(|feature| matches!(feature, DodoPaymentsFeature::Usage))
    }

    pub fn webhooks(&self) -> Option<&DodoWebhooksOptions> {
        self.features
            .iter()
            .rev()
            .find_map(|feature| match feature {
                DodoPaymentsFeature::Webhooks(options) => Some(options),
                _ => None,
            })
    }
}

fn checkout_feature(features: &[DodoPaymentsFeature]) -> Option<&DodoCheckoutOptions> {
    features.iter().rev().find_map(|feature| match feature {
        DodoPaymentsFeature::Checkout(options) => Some(options),
        _ => None,
    })
}

impl fmt::Debug for DodoPaymentsOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DodoPaymentsOptions")
            .field(
                "create_customer_on_sign_up",
                &self.create_customer_on_sign_up,
            )
            .field(
                "has_get_customer_params",
                &self.get_customer_params.is_some(),
            )
            .field("features", &self.features)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum DodoPaymentsFeature {
    Checkout(DodoCheckoutOptions),
    Portal,
    Usage,
    Webhooks(DodoWebhooksOptions),
}

#[derive(Debug, Clone, Default)]
pub struct DodoCheckoutOptions {
    pub products: Option<DodoProducts>,
    pub success_url: Option<String>,
    pub authenticated_users_only: bool,
}

#[derive(Clone)]
pub struct DodoWebhooksOptions {
    webhook_key: Arc<str>,
    pub callbacks: DodoWebhookCallbacks,
}

impl DodoWebhooksOptions {
    pub fn new(webhook_key: impl Into<String>) -> Self {
        Self {
            webhook_key: Arc::from(webhook_key.into()),
            callbacks: DodoWebhookCallbacks::default(),
        }
    }

    pub fn webhook_key(&self) -> &str {
        &self.webhook_key
    }
}

impl fmt::Debug for DodoWebhooksOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DodoWebhooksOptions")
            .field("webhook_key", &"[REDACTED]")
            .field("callbacks", &self.callbacks)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_duplicate_features_follow_runtime_composition() {
        assert!(checkout_feature(&[]).is_none());
        let features = vec![
            DodoPaymentsFeature::Checkout(DodoCheckoutOptions {
                success_url: Some("/first".into()),
                ..DodoCheckoutOptions::default()
            }),
            DodoPaymentsFeature::Portal,
            DodoPaymentsFeature::Checkout(DodoCheckoutOptions {
                success_url: Some("/last".into()),
                ..DodoCheckoutOptions::default()
            }),
        ];
        assert_eq!(
            checkout_feature(&features).and_then(|options| options.success_url.as_deref()),
            Some("/last")
        );
    }

    #[test]
    fn webhook_debug_redacts_the_secret() {
        let options = DodoWebhooksOptions::new("whsec_sensitive_value");
        let debug = format!("{options:?}");
        assert!(!debug.contains("whsec_sensitive_value"));
    }
}
