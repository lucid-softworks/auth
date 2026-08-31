use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A registered OAuth 2.1 client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProviderClient {
    pub id: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    pub client_discovery_id: Option<String>,
    pub disabled: bool,
    pub skip_consent: Option<bool>,
    pub enable_end_session: Option<bool>,
    pub subject_type: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub client_credentials_scopes: Vec<String>,
    pub user_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    /// RFC 7591 client-secret expiry. Better Auth 1.7.2 omits this value from
    /// its adapter schema, so adapter-backed reads return `None`.
    pub expires_at: Option<DateTime<Utc>>,
    pub name: Option<String>,
    pub uri: Option<String>,
    pub icon: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub tos: Option<String>,
    pub policy: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub software_statement: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub token_endpoint_auth_method: Option<String>,
    pub application_type: Option<String>,
    /// Stored JSON text for the client's RFC 7517 JWK Set.
    pub jwks: Option<String>,
    pub jwks_uri: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    #[serde(rename = "requirePKCE")]
    pub require_pkce: Option<bool>,
    pub dpop_bound_access_tokens: bool,
    pub reference_id: Option<String>,
    /// Better Auth stores the open-ended client metadata envelope as JSON.
    pub metadata: Option<serde_json::Value>,
}

/// A protected resource that may be named by an RFC 8707 `resource` value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProviderResource {
    pub id: String,
    pub identifier: String,
    pub name: String,
    pub access_token_ttl: Option<i64>,
    pub refresh_token_ttl: Option<i64>,
    pub signing_algorithm: Option<String>,
    pub signing_key_id: Option<String>,
    pub allowed_scopes: Option<Vec<String>>,
    pub custom_claims: Option<serde_json::Value>,
    pub dpop_bound_access_tokens_required: bool,
    pub disabled: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub policy_version: i64,
    pub metadata: Option<serde_json::Value>,
}

/// A persisted client-to-resource authorization link.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProviderClientResource {
    pub id: String,
    pub client_id: String,
    pub resource_id: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
}

/// An opaque refresh token and its rotation-family state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProviderRefreshToken {
    pub id: String,
    #[serde(skip_serializing)]
    pub token: String,
    pub client_id: String,
    pub session_id: Option<String>,
    pub user_id: String,
    pub reference_id: Option<String>,
    pub authorization_code_id: Option<String>,
    pub resources: Option<Vec<String>>,
    pub requested_user_info_claims: Option<Vec<String>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: Option<DateTime<Utc>>,
    pub rotated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing)]
    pub rotation_replay_response: Option<String>,
    pub rotation_replay_expires_at: Option<DateTime<Utc>>,
    pub auth_time: Option<DateTime<Utc>>,
    pub confirmation: Option<serde_json::Value>,
    pub scopes: Vec<String>,
}

/// A persisted opaque access token. JWT access tokens are intentionally not
/// stored in this model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProviderAccessToken {
    pub id: String,
    #[serde(skip_serializing)]
    pub token: String,
    pub client_id: String,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub reference_id: Option<String>,
    pub authorization_code_id: Option<String>,
    pub resources: Option<Vec<String>>,
    pub requested_user_info_claims: Option<Vec<String>>,
    pub refresh_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: Option<DateTime<Utc>>,
    pub confirmation: Option<serde_json::Value>,
    pub scopes: Vec<String>,
}

/// User consent granted to one OAuth client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProviderConsent {
    pub id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub reference_id: Option<String>,
    pub resources: Option<Vec<String>>,
    pub requested_user_info_claims: Option<Vec<String>>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Single-use `jti` tombstone for assertion-based client authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProviderClientAssertion {
    pub id: String,
    /// Better Auth supplies a truncated base64url SHA-256 digest for replay detection.
    pub jti: String,
    pub expires_at: DateTime<Utc>,
}
