use super::{MemorySsoStore, SsoOptions, SsoStore, VERSION};
use crate::{
    AuthPlugin, PluginArtifactMetadata, PluginClientMetadata, PluginClientPathMethod,
    PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginProvenance,
};
use async_trait::async_trait;
use std::{borrow::Cow, sync::Arc};

const BASE_ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Get, "/sso/saml2/sp/metadata", "spMetadata"),
    endpoint(PluginHttpMethod::Post, "/sso/register", "registerSSOProvider"),
    endpoint(PluginHttpMethod::Post, "/sign-in/sso", "signInSSO"),
    endpoint(PluginHttpMethod::Get, "/sso/callback/:providerId", "callbackSSO"),
    endpoint(PluginHttpMethod::Get, "/sso/callback", "callbackSSOShared"),
    endpoint(PluginHttpMethod::Get, "/sso/saml2/sp/acs/:providerId", "acsEndpoint"),
    endpoint(PluginHttpMethod::Post, "/sso/saml2/sp/acs/:providerId", "acsEndpoint"),
    endpoint(PluginHttpMethod::Get, "/sso/saml2/sp/slo/:providerId", "sloEndpoint"),
    endpoint(PluginHttpMethod::Post, "/sso/saml2/sp/slo/:providerId", "sloEndpoint"),
    endpoint(PluginHttpMethod::Post, "/sso/saml2/logout/:providerId", "initiateSLO"),
    endpoint(PluginHttpMethod::Get, "/sso/providers", "listSSOProviders"),
    endpoint(PluginHttpMethod::Get, "/sso/get-provider", "getSSOProvider"),
    endpoint(PluginHttpMethod::Post, "/sso/update-provider", "updateSSOProvider"),
    endpoint(PluginHttpMethod::Post, "/sso/delete-provider", "deleteSSOProvider"),
];

const DOMAIN_ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Post,
        "/sso/request-domain-verification",
        "requestDomainVerification",
    ),
    endpoint(PluginHttpMethod::Post, "/sso/verify-domain", "verifyDomain"),
];

const CLIENT_PATH_METHODS: &[PluginClientPathMethod] = &[
    PluginClientPathMethod::new("/sso/providers", PluginHttpMethod::Get),
    PluginClientPathMethod::new("/sso/get-provider", PluginHttpMethod::Get),
];

const fn endpoint(
    method: PluginHttpMethod,
    path: &'static str,
    client_method: &'static str,
) -> PluginEndpoint {
    PluginEndpoint {
        method,
        path: Cow::Borrowed(path),
        client_method,
    }
}

#[derive(Clone)]
pub struct SsoPlugin {
    options: SsoOptions,
    store: Arc<dyn SsoStore>,
}

impl Default for SsoPlugin {
    fn default() -> Self {
        Self::new(SsoOptions::default())
    }
}

impl std::fmt::Debug for SsoPlugin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoPlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl SsoPlugin {
    pub fn new(options: SsoOptions) -> Self {
        Self::with_store(options, Arc::new(MemorySsoStore::new()))
    }

    pub fn with_store(options: SsoOptions, store: Arc<dyn SsoStore>) -> Self {
        Self { options, store }
    }

    pub fn options(&self) -> &SsoOptions {
        &self.options
    }

    pub fn store(&self) -> &Arc<dyn SsoStore> {
        &self.store
    }
}

#[async_trait]
impl AuthPlugin for SsoPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        let mut endpoints = BASE_ENDPOINTS.to_vec();
        if self.options.domain_verification {
            endpoints.extend_from_slice(DOMAIN_ENDPOINTS);
        }
        PluginDescriptor {
            id: "sso",
            display_name: "Better Auth Enterprise SSO",
            version: VERSION,
            provenance: PluginProvenance::better_auth(PluginArtifactMetadata::new(
                "@better-auth/sso",
                VERSION,
                "@better-auth/sso",
                "sso",
            )),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(endpoints),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@better-auth/sso",
                    "@better-auth/sso/client",
                    "ssoClient",
                )
                .with_identity("sso-client", VERSION)
                .with_path_methods(CLIENT_PATH_METHODS),
            ),
        }
    }

    fn schema(&self) -> Vec<crate::PluginSchemaTable> {
        vec![super::schema::table(self.options.domain_verification)]
    }
}
