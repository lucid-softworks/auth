use super::{
    MemoryScimStore, ScimError, ScimErrorType, ScimOptions, ScimStore, ScimStoreError, VERSION,
};
#[cfg(feature = "axum")]
use super::ScimScope;
use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginArtifactMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginProvenance, PluginRequestSecurity, PluginSchemaTable,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "axum")]
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{borrow::Cow, sync::Arc};
#[cfg(feature = "axum")]
use std::collections::BTreeMap;

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Post, "/scim/v2/Groups", "createSCIMGroup"),
    endpoint(PluginHttpMethod::Delete, "/scim/v2/Groups/:groupId", "deleteSCIMGroup"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/Groups/:groupId", "getSCIMGroup"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/Groups", "listSCIMGroups"),
    endpoint(PluginHttpMethod::Patch, "/scim/v2/Groups/:groupId", "patchSCIMGroup"),
    endpoint(PluginHttpMethod::Put, "/scim/v2/Groups/:groupId", "replaceSCIMGroup"),
    endpoint(PluginHttpMethod::Post, "/scim/v2/Users", "createSCIMUser"),
    endpoint(PluginHttpMethod::Delete, "/scim/v2/Users/:userId", "deleteSCIMUser"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/Users/:userId", "getSCIMUser"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/Users", "listSCIMUsers"),
    endpoint(PluginHttpMethod::Patch, "/scim/v2/Users/:userId", "patchSCIMUser"),
    endpoint(PluginHttpMethod::Put, "/scim/v2/Users/:userId", "replaceSCIMUser"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/ServiceProviderConfig", "getSCIMServiceProviderConfig"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/Schemas", "getSCIMSchemas"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/Schemas/:schemaId", "getSCIMSchema"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/ResourceTypes", "getSCIMResourceTypes"),
    endpoint(PluginHttpMethod::Get, "/scim/v2/ResourceTypes/:resourceTypeId", "getSCIMResourceType"),
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

#[cfg(feature = "axum")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScimPrincipal {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub credential_id: String,
    pub scopes: Vec<ScimScope>,
}

#[derive(Clone)]
pub struct ScimPlugin {
    pub(crate) options: Arc<ScimOptions>,
    pub(crate) store: Arc<dyn ScimStore>,
}

impl ScimPlugin {
    pub fn new(options: ScimOptions, store: Arc<dyn ScimStore>) -> Result<Self, AuthError> {
        options.validate().map_err(AuthError::InvalidConfiguration)?;
        Ok(Self {
            options: Arc::new(options),
            store,
        })
    }

    pub fn in_memory(options: ScimOptions) -> Result<Self, AuthError> {
        Self::new(options, Arc::new(MemoryScimStore::new()))
    }

    pub fn options(&self) -> &ScimOptions {
        &self.options
    }

    pub fn store(&self) -> &Arc<dyn ScimStore> {
        &self.store
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn authenticate(
        &self,
        authorization: Option<&str>,
        method: &str,
        path: &str,
        headers: BTreeMap<String, String>,
    ) -> Result<ScimPrincipal, ScimError> {
        let token = authorization
            .and_then(|value| {
                let (scheme, token) = value.split_once(char::is_whitespace)?;
                scheme.eq_ignore_ascii_case("bearer").then_some(token.trim())
            })
            .filter(|token| !token.is_empty())
            .ok_or_else(|| ScimError::unauthorized("SCIM bearer token is required"))?;
        let now = Utc::now();
        let mut principal = None;
        for connection in &self.options.connections {
            for credential in &connection.credentials {
                let matches = constant_time_equal(credential.token.as_bytes(), token.as_bytes());
                let active = credential.expires_at.is_none_or(|expires| expires > now);
                if principal.is_none() && matches && active {
                    principal = Some(ScimPrincipal {
                        connection_id: connection.id.clone(),
                        provisioning_domain_id: connection.provisioning_domain_id.clone(),
                        credential_id: credential.id.clone(),
                        scopes: credential.scopes.clone(),
                    });
                }
            }
        }
        let managed_token = token.starts_with("ba_scim_credential_");
        if principal.is_none() && managed_token && self.options.managed_connections.is_some() {
            principal = self.authenticate_managed(token, now).await?;
        }
        if principal.is_none()
            && !managed_token
            && let Some(verifier) = &self.options.authentication
        {
            principal = verifier
                .verify(token, method, path, &headers)
                .await?
                .filter(|verified| verified.expires_at.is_none_or(|expiry| expiry > now))
                .map(|verified| ScimPrincipal {
                    connection_id: verified.connection_id,
                    provisioning_domain_id: verified.provisioning_domain_id,
                    credential_id: verified.credential_id,
                    scopes: verified.scopes,
                });
        }
        let principal = principal
            .ok_or_else(|| ScimError::unauthorized("Invalid SCIM bearer token"))?;
        let scope = required_scope(path, method);
        if !principal.scopes.contains(&scope) {
            return Err(ScimError::new(
                403,
                format!(
                    "The SCIM bearer token is missing the {} scope",
                    scope.as_str()
                ),
            ));
        }
        self.store
            .bind_connection(
                &principal.connection_id,
                &principal.provisioning_domain_id,
                now,
            )
            .await
            .map_err(store_error)?;
        Ok(principal)
    }

    #[cfg(feature = "axum")]
    async fn authenticate_managed(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ScimPrincipal>, ScimError> {
        let Some(options) = &self.options.managed_connections else {
            return Ok(None);
        };
        let Some((credential_id, _)) = token.split_once('.') else {
            return Ok(None);
        };
        let digest = token_digest(&options.credential_hash_secret, token)?;
        let Some((connection, credential)) = self
            .store
            .find_managed_credential(credential_id)
            .await
            .map_err(store_error)?
        else {
            return Ok(None);
        };
        if connection.status == "active"
            && credential.status == "active"
            && credential.hash_version == "v1"
            && credential.expires_at > now
            && constant_time_equal(credential.token_digest.as_bytes(), digest.as_bytes())
        {
            let _ = self
                .store
                .touch_managed_credential(
                    credential_id,
                    now,
                    options.last_used_write_interval_seconds,
                )
                .await;
            return Ok(Some(ScimPrincipal {
                connection_id: connection.connection_id,
                provisioning_domain_id: connection.provisioning_domain_id,
                credential_id: credential.credential_id,
                scopes: credential.scopes,
            }));
        }
        Ok(None)
    }

}

impl std::fmt::Debug for ScimPlugin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScimPlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthPlugin for ScimPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "scim",
            display_name: "Better Auth SCIM",
            version: VERSION,
            provenance: PluginProvenance::better_auth(PluginArtifactMetadata::new(
                "@better-auth/scim",
                VERSION,
                "@better-auth/scim",
                "scim",
            )),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        self.options
            .validate()
            .map_err(AuthError::InvalidConfiguration)
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        super::schema::tables(self.options.managed_connections.is_some())
    }

    fn request_security(&self, _method: PluginHttpMethod, path: &str) -> PluginRequestSecurity {
        if path.starts_with("/scim/v2/") {
            PluginRequestSecurity::RawPublic
        } else {
            PluginRequestSecurity::Browser
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, Arc::new(self.clone()))
    }
}

#[cfg(feature = "axum")]
fn required_scope(path: &str, method: &str) -> ScimScope {
    match (path.contains("/Groups"), matches!(method, "GET" | "HEAD")) {
        (true, true) => ScimScope::GroupsRead,
        (true, false) => ScimScope::GroupsWrite,
        (false, true) => ScimScope::UsersRead,
        (false, false) => ScimScope::UsersWrite,
    }
}

#[cfg(feature = "axum")]
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let maximum = left.len().max(right.len());
    for index in 0..maximum {
        difference |= usize::from(left.get(index).copied().unwrap_or(0)
            ^ right.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

pub(super) fn token_digest(secret: &str, token: &str) -> Result<String, ScimError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| ScimError::new(500, "Unable to initialize managed credential hashing"))?;
    mac.update(token.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub(super) fn store_error(error: ScimStoreError) -> ScimError {
    match error {
        ScimStoreError::NotFound | ScimStoreError::CredentialNotFound => {
            ScimError::new(404, "Resource not found")
        }
        ScimStoreError::DuplicateUserName
        | ScimStoreError::DuplicateExternalId
        | ScimStoreError::DuplicateDisplayName => {
            ScimError::typed(409, error.to_string(), ScimErrorType::Uniqueness)
        }
        ScimStoreError::InvalidMember => {
            ScimError::typed(400, error.to_string(), ScimErrorType::InvalidValue)
        }
        ScimStoreError::BindingConflict => ScimError::new(
            409,
            "The connection provisioningDomainId changed after the connection was first used",
        ),
        ScimStoreError::Decommissioned => {
            ScimError::unauthorized("SCIM connection is decommissioned")
        }
        ScimStoreError::CreationRequestConflict => ScimError::new(
            409,
            super::SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT,
        ),
        ScimStoreError::CredentialLimit => {
            ScimError::new(409, "Maximum active SCIM credentials reached")
        }
        ScimStoreError::Storage(detail) => ScimError::new(500, detail),
    }
}

#[cfg(test)]
mod tests {
    use super::token_digest;

    #[test]
    fn managed_token_digest_matches_the_hmac_sha256_base64url_vector() {
        assert_eq!(
            token_digest("key", "The quick brown fox jumps over the lazy dog").unwrap(),
            "97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg"
        );
    }
}
