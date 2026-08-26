use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Neutral provenance for the credential that created a core session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    Anonymous,
    Password,
    EmailVerified,
    Passkey,
    TwoFactor,
    Extension,
    OAuth,
}

impl AuthenticationMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Password => "password",
            Self::EmailVerified => "email_verified",
            Self::Passkey => "passkey",
            Self::TwoFactor => "two_factor",
            Self::Extension => "extension",
            Self::OAuth => "oauth",
        }
    }
}

/// A user account independent of any HTTP or application framework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthUser {
    pub id: Uuid,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub role: String,
    pub is_anonymous: bool,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A Better Auth 1.7 issuer-qualified external or credential account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub issuer: String,
    pub account_id: String,
    pub provider_id: String,
    #[serde(skip_serializing)]
    pub access_token: Option<String>,
    #[serde(skip_serializing)]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing)]
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input used by a host to provision or update a closed-registration account.
#[derive(Debug, Clone)]
pub struct NewPasswordUser {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password: String,
    pub role: String,
}

/// A persisted WebAuthn credential owned by one account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredPasskey {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub public_key: String,
    pub counter: u32,
    pub device_type: String,
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A durable, one-time verification or protocol challenge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationValue {
    pub id: Uuid,
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VerificationValue {
    pub fn new(
        identifier: impl Into<String>,
        value: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            identifier: identifier.into(),
            value: value.into(),
            expires_at,
            created_at: now,
            updated_at: now,
        }
    }
}

/// A Better Auth-compatible API-key record without its one-time secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    pub id: Uuid,
    pub config_id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub reference_id: String,
    pub refill_interval: Option<i64>,
    pub refill_amount: Option<i64>,
    pub last_refill_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub request_count: i64,
    pub remaining: Option<i64>,
    pub last_request: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub permissions: Option<BTreeMap<String, Vec<String>>>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ApiKey {
    pub fn permits(&self, resource: &str, action: &str) -> bool {
        self.permissions
            .as_ref()
            .and_then(|permissions| permissions.get(resource))
            .is_some_and(|actions| actions.iter().any(|allowed| allowed == action))
    }
}

/// Input for issuing a user-owned API key.
#[derive(Debug, Clone)]
pub struct NewApiKey {
    pub config_id: String,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub permissions: Option<BTreeMap<String, Vec<String>>>,
    pub metadata: Option<serde_json::Value>,
    pub remaining: Option<i64>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
}

/// An API-key record plus its one-time-visible bearer secret.
#[derive(Debug, Clone)]
pub struct IssuedApiKey {
    pub api_key: ApiKey,
    pub key: String,
}

/// A valid API key and its user when the configuration is user-owned.
#[derive(Debug, Clone)]
pub struct VerifiedApiKey {
    pub api_key: ApiKey,
    pub user: Option<AuthUser>,
}

/// Server-side session metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    #[serde(rename = "impersonatedBy", skip_serializing_if = "Option::is_none")]
    pub actor_user_id: Option<Uuid>,
    /// Transient credential context available only on freshly-created native
    /// sessions. Better Auth does not persist this field.
    #[serde(skip)]
    pub authentication_method: Option<AuthenticationMethod>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionWithUser {
    pub session: AuthSession,
    pub user: AuthUser,
}

/// Identity information passed to the host application's authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub actor_id: Uuid,
    pub subject_id: Uuid,
    pub session_id: Uuid,
    /// Host authorization role projected only by an enabled policy plugin.
    pub role: Option<String>,
    pub authentication_method: Option<AuthenticationMethod>,
    /// When the session's credential was verified.
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SessionWithUser {
    pub fn principal(&self) -> Principal {
        Principal {
            actor_id: self.session.actor_user_id.unwrap_or(self.user.id),
            subject_id: self.user.id,
            session_id: self.session.id,
            role: None,
            authentication_method: self.session.authentication_method,
            authenticated_at: self.session.created_at,
            expires_at: self.session.expires_at,
        }
    }
}
