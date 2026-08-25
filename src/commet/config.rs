use super::{CommetClient, CommetWebhookCallbacks};
use crate::{AuthUser, DatabaseHookRequest, PluginApiError};
use async_trait::async_trait;
use std::{fmt, sync::Arc};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommetCustomerCreateParams {
    pub full_name: Option<String>,
    pub domain: Option<String>,
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommetCustomerParamsError {
    #[error("{0}")]
    Api(PluginApiError),
    #[error("{0}")]
    Message(String),
    #[error("Commet customer parameter callback failed")]
    Opaque,
}

impl CommetCustomerParamsError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

#[async_trait]
pub trait CommetCustomerParamsProvider: Send + Sync {
    async fn params(
        &self,
        user: &AuthUser,
        request: &DatabaseHookRequest,
    ) -> Result<CommetCustomerCreateParams, CommetCustomerParamsError>;
}

#[derive(Clone)]
pub struct CommetOptions {
    pub client: Arc<dyn CommetClient>,
    pub create_customer_on_sign_up: bool,
    pub get_customer_create_params: Option<Arc<dyn CommetCustomerParamsProvider>>,
    pub features: Vec<CommetFeature>,
}

impl CommetOptions {
    pub fn new(client: Arc<dyn CommetClient>, features: Vec<CommetFeature>) -> Self {
        Self {
            client,
            create_customer_on_sign_up: false,
            get_customer_create_params: None,
            features,
        }
    }

    #[cfg(any(feature = "axum", test))]
    pub(crate) fn portal(&self) -> Option<&CommetPortalOptions> {
        self.features
            .iter()
            .rev()
            .find_map(|feature| match feature {
                CommetFeature::Portal(options) => Some(options),
                _ => None,
            })
    }

    pub(crate) fn webhooks(&self) -> Option<&CommetWebhooksOptions> {
        self.features
            .iter()
            .rev()
            .find_map(|feature| match feature {
                CommetFeature::Webhooks(options) => Some(options),
                _ => None,
            })
    }
}

impl fmt::Debug for CommetOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommetOptions")
            .field(
                "create_customer_on_sign_up",
                &self.create_customer_on_sign_up,
            )
            .field(
                "has_get_customer_create_params",
                &self.get_customer_create_params.is_some(),
            )
            .field("features", &self.features)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum CommetFeature {
    Portal(CommetPortalOptions),
    Subscriptions(CommetSubscriptionsOptions),
    Features,
    Usage,
    Seats,
    Webhooks(CommetWebhooksOptions),
}

impl CommetFeature {
    pub(crate) fn kind(&self) -> CommetFeatureKind {
        match self {
            Self::Portal(_) => CommetFeatureKind::Portal,
            Self::Subscriptions(_) => CommetFeatureKind::Subscriptions,
            Self::Features => CommetFeatureKind::Features,
            Self::Usage => CommetFeatureKind::Usage,
            Self::Seats => CommetFeatureKind::Seats,
            Self::Webhooks(_) => CommetFeatureKind::Webhooks,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CommetFeatureKind {
    Portal,
    Subscriptions,
    Features,
    Usage,
    Seats,
    Webhooks,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommetPortalOptions {
    pub return_url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommetSubscriptionsOptions {
    /// Preserved because 8.1.0 exposes `plans`, although its runtime never reads it.
    pub plans: Vec<CommetPlanMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommetPlanMapping {
    pub plan_id: String,
    pub slug: String,
}

#[derive(Clone)]
pub struct CommetWebhooksOptions {
    secret: Arc<str>,
    pub callbacks: CommetWebhookCallbacks,
}

impl CommetWebhooksOptions {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: Arc::from(secret.into()),
            callbacks: CommetWebhookCallbacks::default(),
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for CommetWebhooksOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommetWebhooksOptions")
            .field("secret", &"[REDACTED]")
            .field("callbacks", &self.callbacks)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_duplicate_features_follow_the_runtime() {
        let features = [
            CommetFeature::Portal(CommetPortalOptions {
                return_url: Some("/first".into()),
            }),
            CommetFeature::Portal(CommetPortalOptions {
                return_url: Some("/last".into()),
            }),
        ];
        assert_eq!(
            features.iter().rev().find_map(|feature| match feature {
                CommetFeature::Portal(options) => options.return_url.as_deref(),
                _ => None,
            }),
            Some("/last")
        );
        let plans = CommetSubscriptionsOptions {
            plans: vec![CommetPlanMapping {
                plan_id: "plan_1".into(),
                slug: "pro".into(),
            }],
        };
        assert_eq!(plans.plans[0].slug, "pro");
    }

    #[test]
    fn webhook_debug_redacts_the_secret() {
        let options = CommetWebhooksOptions::new("commet_webhook_sensitive");
        assert!(!format!("{options:?}").contains("commet_webhook_sensitive"));
    }
}
