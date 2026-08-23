use crate::{AuthSession, AuthUser, SessionWithUser, StoredPasskey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const COMPATIBLE_BETTER_AUTH_VERSION: &str = "1.7.1";
pub const SESSION_COOKIE_NAME: &str = "better-auth.session_token";
pub const PASSKEY_CHALLENGE_COOKIE_NAME: &str = "better-auth.better-auth-passkey";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameSignInRequest {
    pub username: String,
    pub password: String,
    pub remember_me: Option<bool>,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailSignUpRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    pub image: Option<String>,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    pub remember_me: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailSignInRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    pub remember_me: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasswordResetRequest {
    pub email: String,
    pub redirect_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetCallbackQuery {
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    pub new_password: String,
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendVerificationEmailRequest {
    pub email: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
    #[serde(rename = "callbackURL")]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub image: Option<Option<String>>,
    pub email: Option<serde_json::Value>,
    pub username: Option<String>,
    pub display_username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteUserRequest {
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteUserCallbackQuery {
    pub token: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteUserResponse {
    pub success: bool,
    pub message: &'static str,
}

fn deserialize_optional_field<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
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
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_username: Option<String>,
    pub is_anonymous: bool,
    pub role: String,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_enabled: Option<bool>,
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
}

#[derive(Debug, Serialize)]
pub struct EmailSignUpResponse {
    pub token: Option<String>,
    pub user: BetterAuthUser,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub status: bool,
    pub user: Option<BetterAuthUser>,
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

#[derive(Debug, Serialize)]
pub struct PasswordResetRequestResponse {
    pub status: bool,
    pub message: &'static str,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub user_id: String,
    pub public_key: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub counter: u32,
    pub device_type: String,
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegistrationResponse {
    #[serde(flatten)]
    pub passkey: BetterAuthPasskey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<BetterAuthSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<BetterAuthUser>,
}

impl From<&StoredPasskey> for BetterAuthPasskey {
    fn from(passkey: &StoredPasskey) -> Self {
        Self {
            id: passkey.id.to_string(),
            name: passkey.name.clone(),
            user_id: passkey.user_id.to_string(),
            public_key: passkey.public_key.clone(),
            credential_id: passkey.credential_id.clone(),
            counter: passkey.counter,
            device_type: passkey.device_type.clone(),
            backed_up: passkey.backed_up,
            transports: passkey.transports.clone(),
            created_at: passkey.created_at,
            aaguid: passkey.aaguid.clone(),
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
            additional_fields: user.additional_fields.clone(),
            username: user.username.clone(),
            display_username: user.display_username.clone(),
            is_anonymous: user.is_anonymous,
            role: user.role.clone(),
            banned: user.banned,
            ban_reason: user.ban_reason.clone(),
            ban_expires: user.ban_expires,
            two_factor_enabled: None,
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
