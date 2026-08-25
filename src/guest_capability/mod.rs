#[cfg(feature = "axum")]
mod axum;

use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginDescriptor, PluginEndpoint, PluginHttpMethod,
    PluginMigration, Principal, SessionWithUser, SignInResult,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Get,
        "/guest-grants",
        "guestCapability.list",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/guest-grants",
        "guestCapability.issue",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/guest-grants/revoke",
        "guestCapability.revoke",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/sign-in/guest-grant",
        "guestCapability.redeem",
    ),
];

const fn endpoint(
    method: PluginHttpMethod,
    path: &'static str,
    client_method: &'static str,
) -> PluginEndpoint {
    PluginEndpoint {
        method,
        path: std::borrow::Cow::Borrowed(path),
        client_method,
    }
}

const MIGRATIONS: &[PluginMigration] = &[PluginMigration::borrowed(
    "lucid-guest-capability-schema",
    "Optional lucid guest-capability grants and session links",
    include_str!("../../migrations/guest_capability_plugin.sql"),
)];

/// A time-bounded lucid extension grant that can be exchanged for a guest session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestGrant {
    pub id: Uuid,
    pub label: String,
    #[serde(skip_serializing)]
    pub token_hash: Option<String>,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<i32>,
    pub uses: i32,
    pub created_by: Uuid,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewGuestGrant {
    pub label: String,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct IssuedGuestGrant {
    pub grant: GuestGrant,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct GuestGrantSignInResult {
    pub token: String,
    pub session: SessionWithUser,
    pub grant_id: Uuid,
}

impl GuestGrantSignInResult {
    pub(crate) fn new(result: SignInResult, grant_id: Uuid) -> Self {
        Self {
            token: result.token,
            session: result.session,
            grant_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestCapabilityPrincipal {
    pub principal: Principal,
    pub guest_grant_id: Uuid,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<String>,
}

#[async_trait]
pub trait GuestCapabilityStore: Send + Sync {
    async fn create_guest_grant(&self, grant: GuestGrant) -> Result<GuestGrant, AuthError>;

    async fn consume_guest_grant(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<GuestGrant>, AuthError>;

    async fn attach_guest_session(
        &self,
        grant_id: Uuid,
        session_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError>;

    async fn find_guest_grant_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<GuestGrant>, AuthError>;

    async fn list_guest_grants(&self) -> Result<Vec<GuestGrant>, AuthError>;

    /// Revokes a grant and invalidates every attached session atomically.
    async fn revoke_guest_grant(
        &self,
        grant_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct GuestCapabilityPlugin {
    pub(crate) store: Arc<dyn GuestCapabilityStore>,
}

impl GuestCapabilityPlugin {
    pub fn new(store: Arc<dyn GuestCapabilityStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl AuthPlugin for GuestCapabilityPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "lucid-guest-capability",
            display_name: "lucid-auth Guest Capabilities",
            version: env!("CARGO_PKG_VERSION"),
            provenance: crate::PluginProvenance::lucid_extension(),
            dependencies: &["lucid-owner-policy"],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn migrations(&self) -> std::borrow::Cow<'_, [PluginMigration]> {
        std::borrow::Cow::Borrowed(MIGRATIONS)
    }

    async fn validate_session(&self, session: &SessionWithUser) -> Result<bool, AuthError> {
        let Some(grant) = self
            .store
            .find_guest_grant_for_session(session.session.id)
            .await?
        else {
            return Ok(true);
        };
        let now = Utc::now();
        Ok(grant.revoked_at.is_none() && grant.valid_from <= now && grant.expires_at > now)
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service)
    }
}
