use super::{SentinelOptions, VERSION};
use crate::{
    AuthPlugin, PluginArtifactMetadata, PluginClientMetadata, PluginCookie, PluginDescriptor,
    PluginProvenance,
};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc};

const COOKIES: &[PluginCookie] = &[PluginCookie {
    name: "__infra-rid",
}];

#[derive(Clone)]
pub struct SentinelPlugin {
    options: Arc<SentinelOptions>,
}

impl SentinelPlugin {
    pub fn new(options: SentinelOptions) -> Self {
        Self {
            options: Arc::new(options),
        }
    }

    pub fn options(&self) -> &SentinelOptions {
        &self.options
    }

    /// Metadata for the separately published React Native/Expo client.
    pub fn native_client_metadata() -> PluginClientMetadata {
        PluginClientMetadata::official(
            "@better-auth/infra",
            "@better-auth/infra/native",
            "sentinelNativeClient",
        )
        .with_identity("sentinel", VERSION)
    }
}

impl Default for SentinelPlugin {
    fn default() -> Self {
        Self::new(SentinelOptions::default())
    }
}

impl fmt::Debug for SentinelPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SentinelPlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthPlugin for SentinelPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "sentinel",
            display_name: "Better Auth Infrastructure Sentinel",
            version: VERSION,
            provenance: PluginProvenance::PinnedBetterAuthPort {
                better_auth_version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                server: PluginArtifactMetadata::new(
                    "@better-auth/infra",
                    VERSION,
                    "@better-auth/infra",
                    "sentinel",
                ),
            },
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(&[]),
            cookies: COOKIES,
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@better-auth/infra",
                    "@better-auth/infra/client",
                    "sentinelClient",
                )
                .with_identity("sentinel", VERSION),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_the_exact_published_surfaces() {
        let descriptor = SentinelPlugin::default().descriptor();
        assert_eq!(descriptor.id, "sentinel");
        assert_eq!(descriptor.version, "0.4.3");
        assert!(descriptor.endpoints.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        assert_eq!(descriptor.cookies, COOKIES);

        let browser = descriptor.client.unwrap();
        assert_eq!(browser.factory, "sentinelClient");
        assert_eq!(browser.client_id, Some("sentinel"));
        let native = SentinelPlugin::native_client_metadata();
        assert_eq!(native.import_path, "@better-auth/infra/native");
        assert_eq!(native.factory, "sentinelNativeClient");
        assert_eq!(native.client_id, Some("sentinel"));
    }
}
