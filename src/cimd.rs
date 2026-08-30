//! Better Auth 1.7.1 Client ID Metadata Document compatibility.

mod jwks;
mod metadata;
mod schema;
mod uri;
mod url;

pub use metadata::{
    CimdMetadata, CimdMetadataProfile, CimdMetadataValidationOptions,
    CimdMetadataValidationResult, validate_cimd_metadata,
};
pub use url::{is_cimd_client_id_url_candidate, validate_client_id_url};

/// Published `@better-auth/cimd` compatibility version.
pub const CIMD_VERSION: &str = "1.7.1";
