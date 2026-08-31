//! Better Auth 1.7.2 Client ID Metadata Document compatibility.

mod cache;
mod discovery;
mod document;
mod duration;
mod fetch;
mod governor;
mod jwks;
mod metadata;
mod options;
mod persistence;
mod plugin;
mod schema;
mod uri;
mod url;

pub use metadata::{
    CimdMetadata, CimdMetadataProfile, CimdMetadataValidationOptions,
    CimdMetadataValidationResult, validate_cimd_metadata,
};
pub use url::{is_cimd_client_id_url_candidate, validate_client_id_url};
pub use options::{
    CimdClientCreatedEvent, CimdClientLifecycle, CimdClientRefreshedEvent, CimdConfigError,
    CimdDuration, CimdMetadataDocumentUrlPolicy, CimdMetadataFetchPolicy, CimdOptions,
};
pub use discovery::{CimdClientDiscovery, create_cimd_client_discovery};
pub use plugin::{CimdPlugin, cimd};

/// Published `@better-auth/cimd` compatibility version.
pub const CIMD_VERSION: &str = "1.7.2";
pub use fetch::{
    CimdFetchError, CimdFetchRequest, CimdFetchResponse, CimdMetadataResourceFetcher,
};
#[cfg(not(target_arch = "wasm32"))]
pub use fetch::{NativeCimdMetadataFetcher, fetch_client_metadata_resource};
