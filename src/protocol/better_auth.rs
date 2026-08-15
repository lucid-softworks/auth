use crate::{AuthSession, AuthUser, SessionWithUser, StoredPasskey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const COMPATIBLE_BETTER_AUTH_VERSION: &str = "1.6.29";
pub const SESSION_COOKIE_NAME: &str = "better-auth.session_token";
pub const PASSKEY_CHALLENGE_COOKIE_NAME: &str = "better-auth.better-auth-passkey";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameSignInRequest {
    pub username: String,
    pub password: String,
    pub remember_me: Option<bool>,
    pub callback_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UsernameAvailabilityRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct UsernameAvailabilityResponse {
    pub available: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BetterAuthUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub is_anonymous: bool,
    pub must_change_password: bool,
    pub role: String,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BetterAuthSession {
    pub id: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub impersonated_by: Option<String>,
    pub assurance: String,
    pub guest_grant_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session: BetterAuthSession,
    pub user: BetterAuthUser,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInResponse {
    pub redirect: bool,
    pub token: String,
    pub url: Option<String>,
    pub user: BetterAuthUser,
    pub two_factor_redirect: bool,
    pub two_factor_methods: Vec<String>,
    pub mfa_setup_required: bool,
}

#[derive(Debug, Deserialize)]
pub struct GenerateBackupCodesRequest {
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateBackupCodesResponse {
    pub status: bool,
    pub backup_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyBackupCodeRequest {
    pub code: String,
    pub disable_session: Option<bool>,
    pub trust_device: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct VerifyBackupCodeResponse {
    pub token: String,
    pub user: BetterAuthUser,
}

#[derive(Debug, Serialize)]
pub struct RecoveryCodeStatusResponse {
    pub remaining: usize,
}

#[derive(Debug, Serialize)]
pub struct AnonymousSignInResponse {
    pub token: String,
    pub user: BetterAuthUser,
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub new_password: String,
    pub current_password: String,
    pub revoke_other_sessions: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordResponse {
    pub token: Option<String>,
    pub user: BetterAuthUser,
}

#[derive(Debug, Deserialize)]
pub struct RevokeSessionRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct DeletePasskeyRequest {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePasskeyRequest {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UpdatePasskeyResponse {
    pub passkey: BetterAuthPasskey,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BetterAuthPasskey {
    pub id: String,
    pub name: Option<String>,
    pub user_id: String,
    pub credential_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&StoredPasskey> for BetterAuthPasskey {
    fn from(passkey: &StoredPasskey) -> Self {
        Self {
            id: passkey.id.to_string(),
            name: passkey.name.clone(),
            user_id: passkey.user_id.to_string(),
            credential_id: passkey.credential_id.clone(),
            created_at: passkey.created_at,
            updated_at: passkey.updated_at,
        }
    }
}

impl From<&AuthUser> for BetterAuthUser {
    fn from(user: &AuthUser) -> Self {
        Self {
            id: user.id.to_string(),
            name: user.name.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            image: user.image.clone(),
            created_at: user.created_at,
            updated_at: user.updated_at,
            username: user.username.clone(),
            display_username: user.display_username.clone(),
            is_anonymous: user.is_anonymous,
            must_change_password: user.must_change_password,
            role: user.role.clone(),
            banned: user.banned,
            ban_reason: user.ban_reason.clone(),
            ban_expires: user.ban_expires,
        }
    }
}

impl BetterAuthSession {
    pub fn from_session(session: &AuthSession, token: impl Into<String>) -> Self {
        Self {
            id: session.id.to_string(),
            user_id: session.user_id.to_string(),
            expires_at: session.expires_at,
            token: token.into(),
            created_at: session.created_at,
            updated_at: session.updated_at,
            ip_address: session.ip_address.clone(),
            user_agent: session.user_agent.clone(),
            impersonated_by: session.actor_user_id.map(|id| id.to_string()),
            assurance: session.assurance.as_str().into(),
            guest_grant_id: session.guest_grant_id.map(|id| id.to_string()),
        }
    }
}

impl SessionResponse {
    pub fn new(value: &SessionWithUser, token: impl Into<String>) -> Self {
        Self {
            session: BetterAuthSession::from_session(&value.session, token),
            user: BetterAuthUser::from(&value.user),
        }
    }
}
