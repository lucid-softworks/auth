use crate::{AuthSession, AuthUser, SessionWithUser};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const COMPATIBLE_BETTER_AUTH_VERSION: &str = "1.6.29";
pub const SESSION_COOKIE_NAME: &str = "better-auth.session_token";

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
pub struct SignInResponse {
    pub redirect: bool,
    pub token: String,
    pub url: Option<String>,
    pub user: BetterAuthUser,
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
pub struct ErrorResponse {
    pub code: &'static str,
    pub message: &'static str,
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
