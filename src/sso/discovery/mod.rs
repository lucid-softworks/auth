mod document;
mod error;
mod fetch;
mod url;

pub use document::{
    OidcConfig, OidcDiscoveryDocument, REQUIRED_DISCOVERY_FIELDS,
    SsoTokenEndpointAuthentication,
    needs_runtime_discovery, normalize_discovery_urls, select_token_endpoint_auth_method,
    validate_discovery_document,
};
pub use error::{DiscoveryError, DiscoveryErrorCode};
pub use fetch::{fetch_discovery_document, validate_oidc_endpoint_egress};
pub use url::{
    compute_discovery_url, normalize_url, validate_discovery_url, validate_oidc_endpoint_url,
};
