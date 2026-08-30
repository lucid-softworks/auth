//! Native enterprise SSO surface compatible with `@better-auth/sso` 1.7.1.

mod config;
mod database;
#[cfg(feature = "axum")]
mod dns;
mod discovery;
#[cfg(feature = "axum")]
mod axum;
mod plugin;
#[cfg(feature = "axum")]
mod oidc_provider;
mod provider_reference;
mod schema;
mod store;
mod timestamp;

pub use config::SsoOptions;
pub use database::DatabaseSsoStore;
#[cfg(feature = "axum")]
pub use dns::{SsoDnsResolver, SystemSsoDnsResolver};
pub use discovery::{
    DiscoveryError, DiscoveryErrorCode, OidcConfig, OidcDiscoveryDocument,
    REQUIRED_DISCOVERY_FIELDS,
    SsoTokenEndpointAuthentication, compute_discovery_url, fetch_discovery_document,
    needs_runtime_discovery, normalize_discovery_urls, normalize_url,
    select_token_endpoint_auth_method, validate_discovery_document, validate_discovery_url,
    validate_oidc_endpoint_url,
};
pub use plugin::SsoPlugin;
pub use store::{
    MemorySsoStore, NewSsoProvider, SsoProvider, SsoProviderUpdate, SsoStore, SsoStoreError,
};
pub use timestamp::{
    SamlConditions, SamlTimestampError, SamlTimestampOptions, validate_saml_timestamp,
    validate_saml_timestamp_at,
};

/// Published `@better-auth/sso` compatibility target.
pub const VERSION: &str = "1.7.1";
pub const DEFAULT_CLOCK_SKEW_MS: i64 = 300_000;
pub const DEFAULT_MAX_SAML_RESPONSE_SIZE: usize = 256 * 1024;
pub const DEFAULT_MAX_SAML_METADATA_SIZE: usize = 100 * 1024;
