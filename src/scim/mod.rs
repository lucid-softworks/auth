//! Native inbound SCIM 2.0 service compatible with `@better-auth/scim` 1.7.1.

#[cfg(feature = "axum")]
mod axum;
mod config;
#[cfg(feature = "axum")]
mod discovery;
mod error;
mod memory;
mod managed;
mod model;
mod plugin;
mod schema;
mod store;
mod timestamp;

pub use config::{
    ScimBearerCredential, ScimBearerTokenVerifier, ScimConnection, ScimManagedConnectionOptions,
    ScimOptions, ScimScope, ScimVerifiedBearer,
};
pub use error::{ScimError, ScimErrorBody, ScimErrorType};
pub use memory::MemoryScimStore;
pub use model::{
    ScimAddress, ScimEmail, ScimEnterpriseUser, ScimGroup, ScimGroupMember, ScimListResponse,
    ScimEntitlement, ScimManagedConnection, ScimManagedConnectionEvent, ScimManagedCredential,
    ScimManager, ScimName, ScimPatchOperation, ScimPatchRequest, ScimPhoneNumber, ScimRole,
    ScimUser,
};
pub use plugin::ScimPlugin;
pub use store::{ScimConnectionBinding, ScimStore, ScimStoreError};

/// Published `@better-auth/scim` compatibility target.
pub const VERSION: &str = "1.7.1";
pub const SCIM_MEDIA_TYPE: &str = "application/scim+json";
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const SCIM_LIST_RESPONSE_SCHEMA: &str =
    "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_ENTERPRISE_USER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCIM_PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT: &str =
    "SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT";

pub(crate) fn random_urlsafe(length: usize) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngExt as _;

    let mut output = String::new();
    while output.len() < length {
        let bytes: [u8; 32] = rand::rng().random();
        output.push_str(&URL_SAFE_NO_PAD.encode(bytes));
    }
    output.truncate(length);
    output
}
