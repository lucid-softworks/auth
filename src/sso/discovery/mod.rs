mod document;
mod error;
mod url;

pub use document::{
    OidcConfig, OidcDiscoveryDocument, REQUIRED_DISCOVERY_FIELDS,
    SsoTokenEndpointAuthentication,
    needs_runtime_discovery, normalize_discovery_urls, select_token_endpoint_auth_method,
    validate_discovery_document,
};
pub use error::{DiscoveryError, DiscoveryErrorCode};
pub use url::{
    compute_discovery_url, normalize_url, validate_discovery_url, validate_oidc_endpoint_url,
};
