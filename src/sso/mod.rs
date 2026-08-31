//! Native enterprise SSO surface compatible with `@better-auth/sso` 1.7.1.

mod config;
mod database;
#[cfg(feature = "axum")]
mod dns;
mod discovery;
#[cfg(feature = "axum")]
mod axum;
mod plugin;
mod mutation_guard;
mod organization_provisioning;
mod private_key;
mod provisioning;
mod resolution;
#[cfg(feature = "axum")]
mod oidc_provider;
mod provider_reference;
mod saml;
mod schema;
mod store;
mod timestamp;

#[cfg(feature = "axum")]
pub(crate) use axum::sanitize::provider as sanitize_provider;
#[cfg(feature = "axum")]
pub(crate) use axum::mutation::guard::{
    delete as delete_provider_guarded, update as update_provider_guarded,
};

pub use config::{
    SsoDefaultProvider, SsoFieldMappings, SsoOptions, SsoProviderFieldMappings,
    SsoProviderSchema, SsoSchema,
};
pub use database::DatabaseSsoStore;
#[cfg(feature = "axum")]
pub use dns::{SsoDnsResolver, SystemSsoDnsResolver};
pub use discovery::{
    DiscoveryError, DiscoveryErrorCode, OidcConfig, OidcDiscoveryDocument,
    REQUIRED_DISCOVERY_FIELDS,
    SsoTokenEndpointAuthentication, compute_discovery_url, fetch_discovery_document,
    needs_runtime_discovery, normalize_discovery_urls, normalize_url,
    select_token_endpoint_auth_method, validate_discovery_document, validate_discovery_url,
    validate_oidc_endpoint_egress, validate_oidc_endpoint_url,
};
pub use plugin::SsoPlugin;
pub use mutation_guard::{
    SsoMutationProvider, SsoProviderMutationGuard, SsoProviderMutationGuardContext,
    SsoProviderMutationGuardInput,
};
pub use organization_provisioning::{
    SsoOrganizationProvisioningOptions, SsoOrganizationRole, SsoOrganizationRoleInput,
    SsoOrganizationRoleResolver,
};
pub use private_key::{SsoPrivateKey, SsoPrivateKeyRequest, SsoPrivateKeyResolver};
pub use provider_reference::{SsoProviderReference, SsoProviderSource};
pub use provisioning::{SsoProvisioningInput, SsoUserProvisioner};
pub use resolution::{
    SsoProviderUserProfile, SsoUserProfilePolicy, SsoUserResolution,
    SsoUserResolutionContext, SsoUserResolutionInput, SsoUserResolver,
};
pub use saml::{
    DataEncryptionAlgorithm, DeprecatedAlgorithmBehavior, DigestAlgorithm,
    KeyEncryptionAlgorithm, SamlAlgorithmError, SamlAlgorithmOptions, SamlConfigurationError,
    SamlServiceProviderPolicy, SignatureAlgorithm,
};
pub use schema::SsoSchemaError;
#[cfg(feature = "axum")]
pub use saml::{
    derive_saml_identity_provider_entity_id, derive_saml_service_provider_policy,
};
#[cfg(feature = "axum")]
pub(crate) use saml::{validate_configuration_algorithms, validate_response_algorithms};
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
