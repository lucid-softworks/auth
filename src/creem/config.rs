#[cfg(feature = "axum")]
use super::{CreemHttpTransport, CreemProviderConfig};
use super::{CreemSchema, CreemTransport, CreemWebhookCallbacks};
use std::{fmt, sync::Arc};

#[derive(Clone)]
pub struct CreemOptions {
    pub api_key: String,
    pub webhook_secret: Option<String>,
    pub test_mode: bool,
    pub default_success_url: Option<String>,
    pub persist_subscriptions: bool,
    pub schema: CreemSchema,
    pub callbacks: CreemWebhookCallbacks,
    transport: Option<Arc<dyn CreemTransport>>,
}

impl CreemOptions {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            ..Self::default()
        }
    }

    pub fn with_transport(api_key: impl Into<String>, transport: Arc<dyn CreemTransport>) -> Self {
        Self {
            api_key: api_key.into(),
            transport: Some(transport),
            ..Self::default()
        }
    }

    pub fn webhook_enabled(&self) -> bool {
        self.webhook_secret
            .as_deref()
            .is_some_and(|secret| !secret.is_empty())
    }

    #[cfg(feature = "axum")]
    pub(crate) fn transport(&self) -> Arc<dyn CreemTransport> {
        self.transport.clone().unwrap_or_else(|| {
            let config = if self.test_mode {
                CreemProviderConfig::test(self.api_key.clone())
            } else {
                CreemProviderConfig::production(self.api_key.clone())
            };
            Arc::new(CreemHttpTransport::new(config))
        })
    }
}

impl Default for CreemOptions {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            webhook_secret: None,
            test_mode: false,
            default_success_url: None,
            persist_subscriptions: true,
            schema: CreemSchema::default(),
            callbacks: CreemWebhookCallbacks::default(),
            transport: None,
        }
    }
}

impl fmt::Debug for CreemOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreemOptions")
            .field("api_key", &"[REDACTED]")
            .field(
                "webhook_secret",
                &self.webhook_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("test_mode", &self.test_mode)
            .field("default_success_url", &self.default_success_url)
            .field("persist_subscriptions", &self.persist_subscriptions)
            .field("schema", &self.schema)
            .field("callbacks", &self.callbacks)
            .field("custom_transport", &self.transport.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_truthy_webhook_registration_match_upstream() {
        let mut options = CreemOptions::default();
        assert!(options.persist_subscriptions);
        assert!(!options.test_mode);
        assert!(!options.webhook_enabled());
        options.webhook_secret = Some(String::new());
        assert!(!options.webhook_enabled());
        options.webhook_secret = Some("whsec_test".into());
        assert!(options.webhook_enabled());
    }

    #[test]
    fn debug_never_exposes_provider_or_webhook_secrets() {
        let mut options = CreemOptions::new("creem_secret");
        options.webhook_secret = Some("whsec_sensitive_value".into());
        let debug = format!("{options:?}");
        assert!(!debug.contains("creem_secret"));
        assert!(!debug.contains("whsec_sensitive_value"));
    }
}
