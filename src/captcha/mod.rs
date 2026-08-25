use crate::{AuthPlugin, PluginClientMetadata, PluginDescriptor};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc};

mod config;
mod error;
#[cfg(feature = "axum")]
mod path;
#[cfg(feature = "axum")]
mod verify;

pub use config::{
    CaptchaConfig, CaptchaFoxOptions, CaptchaProvider, CloudflareTurnstileOptions,
    GoogleRecaptchaOptions, HCaptchaOptions,
};
pub use error::CaptchaError;
#[cfg(feature = "axum")]
use path::ProtectedEndpoints;

pub struct CaptchaPlugin {
    config: Arc<CaptchaConfig>,
    #[cfg(feature = "axum")]
    endpoints: ProtectedEndpoints,
}

impl CaptchaPlugin {
    pub fn new(config: CaptchaConfig) -> Self {
        #[cfg(feature = "axum")]
        let endpoints = ProtectedEndpoints::new(config.endpoints());
        Self {
            config: Arc::new(config),
            #[cfg(feature = "axum")]
            endpoints,
        }
    }

    pub fn config(&self) -> &CaptchaConfig {
        &self.config
    }
}

impl fmt::Debug for CaptchaPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptchaPlugin")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthPlugin for CaptchaPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "captcha",
            display_name: "Better Auth Captcha",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::current(
                "better-auth",
                "better-auth/plugins",
                "captcha",
            )),
        }
    }

    #[cfg(feature = "axum")]
    async fn on_request(
        &self,
        service: &crate::AuthService,
        request: axum::extract::Request,
    ) -> Result<axum::extract::Request, axum::response::Response> {
        verify::intercept(service, &self.config, &self.endpoints, request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_has_only_the_server_plugin_metadata() {
        let plugin = CaptchaPlugin::new(CaptchaConfig::HCaptcha(HCaptchaOptions::new("secret")));
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "captcha");
        assert!(descriptor.endpoints.is_empty());
        assert!(descriptor.cookies.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        assert!(descriptor.middleware.is_empty());
        let metadata = descriptor.client.unwrap();
        assert_eq!(metadata.import_path, "better-auth/plugins");
        assert_eq!(metadata.factory, "captcha");
        assert_eq!(plugin.config().provider().as_str(), "hcaptcha");
    }

    #[test]
    fn debug_output_never_exposes_the_secret() {
        let plugin = CaptchaPlugin::new(CaptchaConfig::CaptchaFox(CaptchaFoxOptions::new(
            "top-secret",
        )));
        let output = format!("{plugin:?}");
        assert!(!output.contains("top-secret"));
        assert!(output.contains("[REDACTED]"));
    }
}
