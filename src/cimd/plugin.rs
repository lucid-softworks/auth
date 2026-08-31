use super::{CIMD_VERSION, CimdClientDiscovery, CimdConfigError, CimdOptions};
use crate::{AuthPlugin, OAuthProviderExtension, PluginDescriptor, PluginProvenance};
use async_trait::async_trait;
use std::{borrow::Cow, sync::Arc};

#[derive(Clone)]
pub struct CimdPlugin {
    discovery: Arc<CimdClientDiscovery>,
}

impl std::fmt::Debug for CimdPlugin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CimdPlugin")
            .finish_non_exhaustive()
    }
}

pub fn cimd(options: CimdOptions) -> Result<CimdPlugin, CimdConfigError> {
    Ok(CimdPlugin {
        discovery: super::create_cimd_client_discovery(options)?,
    })
}

impl CimdPlugin {
    pub fn discovery(&self) -> Arc<CimdClientDiscovery> {
        self.discovery.clone()
    }
}

#[async_trait]
impl AuthPlugin for CimdPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "cimd",
            display_name: "Better Auth Client ID Metadata Document",
            version: CIMD_VERSION,
            provenance: PluginProvenance::pinned_upstream(
                "@better-auth/cimd",
                CIMD_VERSION,
                "@better-auth/cimd",
                "cimd",
            ),
            dependencies: &["oauth-provider"],
            conflicts: &[],
            endpoints: Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn oauth_provider_extensions(&self) -> Vec<Arc<dyn OAuthProviderExtension>> {
        vec![self.discovery.clone()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CimdFetchError, CimdFetchRequest, CimdFetchResponse, CimdMetadataResourceFetcher};

    struct Fetcher;

    #[async_trait]
    impl CimdMetadataResourceFetcher for Fetcher {
        async fn fetch(
            &self,
            _request: CimdFetchRequest,
        ) -> Result<CimdFetchResponse, CimdFetchError> {
            unreachable!()
        }
    }

    #[test]
    fn descriptor_matches_pinned_upstream_plugin() {
        let plugin = cimd(CimdOptions::new(Arc::new(Fetcher))).unwrap();
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "cimd");
        assert_eq!(descriptor.version, "1.7.2");
        assert_eq!(descriptor.dependencies, &["oauth-provider"]);
        assert!(descriptor.endpoints.is_empty());
        assert!(descriptor.client.is_none());
        assert!(Arc::ptr_eq(&plugin.discovery(), &plugin.discovery()));
    }
}
