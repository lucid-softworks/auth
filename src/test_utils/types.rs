use crate::{AuthError, AuthSession, AuthUser};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TestUtilsOptions {
    pub capture_otp: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TestUserOverrides {
    pub id: Option<Uuid>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub image: Option<Option<String>>,
    pub additional_fields: Map<String, Value>,
    pub role: Option<String>,
    pub is_anonymous: Option<bool>,
    pub banned: Option<bool>,
    pub ban_reason: Option<Option<String>>,
    pub ban_expires: Option<Option<DateTime<Utc>>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct TestOrganizationOverrides {
    pub id: Option<Uuid>,
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<Option<String>>,
    pub metadata: Option<Option<Value>>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: String,
    pub expires: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct TestLoginResult {
    pub session: AuthSession,
    pub user: AuthUser,
    pub headers: BTreeMap<String, String>,
    pub cookies: Vec<TestCookie>,
    pub token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TestUtilsError {
    #[error("User not found: {0}")]
    UserNotFound(Uuid),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

#[derive(Clone, Copy)]
pub struct TestHelpers<'a> {
    pub(crate) service: &'a crate::AuthService,
}

#[derive(Clone, Copy)]
pub struct TestOrganizationHelpers<'a> {
    pub(crate) service: &'a crate::AuthService,
}

#[derive(Clone, Copy)]
pub struct TestOtpHelpers<'a> {
    pub(crate) plugin: &'a super::TestUtilsPlugin,
}

impl TestLoginResult {
    pub fn session_with_user(&self) -> crate::SessionWithUser {
        crate::SessionWithUser {
            session: self.session.clone(),
            user: self.user.clone(),
        }
    }
}

impl TestOtpHelpers<'_> {
    pub fn get_otp(&self, identifier: &str) -> Option<String> {
        self.plugin.get_otp(identifier)
    }

    pub fn clear_otps(&self) {
        self.plugin.clear_otps();
    }
}
