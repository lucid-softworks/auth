use super::model::{
    OAuthProviderAccessToken, OAuthProviderClient, OAuthProviderClientAssertion,
    OAuthProviderClientResource, OAuthProviderConsent, OAuthProviderRefreshToken,
    OAuthProviderResource,
};
use crate::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthClientRegistrationMode {
    Create,
    RefreshDiscovered { discovery_id: String },
}

#[derive(Debug, Clone)]
pub struct OAuthClientRegistrationWrite {
    pub client: OAuthProviderClient,
    pub resource_ids: Vec<String>,
    pub mode: OAuthClientRegistrationMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthClientRegistrationOutcome {
    Created(OAuthProviderClient),
    Updated(OAuthProviderClient),
    ClientIdTaken,
    DiscoveryOwnershipChanged,
    ResourceNotFound(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthClientResourceLinkOutcome {
    Linked(OAuthProviderClientResource),
    AlreadyLinked(OAuthProviderClientResource),
    ClientNotFound,
    ResourceNotFound,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthTokenIssuance {
    pub access_token: Option<OAuthProviderAccessToken>,
    pub refresh_token: Option<OAuthProviderRefreshToken>,
}

#[derive(Debug, Clone)]
pub struct OAuthRefreshRotation {
    pub previous_refresh_id: Uuid,
    pub rotated_at: DateTime<Utc>,
    pub replay_expires_at: Option<DateTime<Utc>>,
    pub next_refresh_token: OAuthProviderRefreshToken,
    pub access_token: Option<OAuthProviderAccessToken>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthRefreshRotationOutcome {
    Rotated(OAuthProviderRefreshToken),
    AlreadyConsumed(OAuthProviderRefreshToken),
    NotFound,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OAuthTokenRevocationCount {
    pub access_tokens: usize,
    pub refresh_tokens: usize,
}

/// Token identifiers captured before a session row is deleted. PostgreSQL
/// clears token `sessionId` foreign keys as part of that delete, so the plan is
/// applied by identifier afterward.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthSessionLogoutPlan {
    pub client_ids: Vec<String>,
    pub access_token_ids: Vec<Uuid>,
    pub refresh_token_ids: Vec<Uuid>,
}

/// Client persistence, including the registration transaction that writes a
/// client and every requested resource link as one unit.
#[async_trait]
pub trait OAuthProviderClientStore: Send + Sync {
    async fn find_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError>;

    async fn list_oauth_clients(
        &self,
        user_id: Option<Uuid>,
        reference_id: Option<&str>,
    ) -> Result<Vec<OAuthProviderClient>, AuthError>;

    async fn persist_oauth_client_registration(
        &self,
        write: OAuthClientRegistrationWrite,
    ) -> Result<OAuthClientRegistrationOutcome, AuthError>;

    async fn update_oauth_client(
        &self,
        client: OAuthProviderClient,
    ) -> Result<Option<OAuthProviderClient>, AuthError>;

    async fn delete_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError>;
}

#[async_trait]
pub trait OAuthProviderResourceStore: Send + Sync {
    async fn find_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError>;

    async fn list_oauth_resources(&self) -> Result<Vec<OAuthProviderResource>, AuthError>;

    async fn create_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError>;

    async fn update_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError>;

    async fn delete_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError>;

    async fn list_oauth_client_resources(
        &self,
        client_id: &str,
    ) -> Result<Vec<OAuthProviderClientResource>, AuthError>;

    async fn link_oauth_client_resource(
        &self,
        link: OAuthProviderClientResource,
    ) -> Result<OAuthClientResourceLinkOutcome, AuthError>;

    async fn unlink_oauth_client_resource(
        &self,
        client_id: &str,
        resource_id: &str,
    ) -> Result<Option<OAuthProviderClientResource>, AuthError>;
}

#[async_trait]
pub trait OAuthProviderConsentStore: Send + Sync {
    async fn find_oauth_consent(&self, id: Uuid)
    -> Result<Option<OAuthProviderConsent>, AuthError>;

    async fn find_oauth_consent_for_grant(
        &self,
        client_id: &str,
        user_id: Uuid,
        reference_id: Option<&str>,
    ) -> Result<Option<OAuthProviderConsent>, AuthError>;

    async fn list_oauth_consents(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OAuthProviderConsent>, AuthError>;

    async fn upsert_oauth_consent(
        &self,
        consent: OAuthProviderConsent,
    ) -> Result<OAuthProviderConsent, AuthError>;

    async fn delete_oauth_consent(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderConsent>, AuthError>;
}

/// Token persistence exposes issuance and rotation as atomic operations. This
/// prevents endpoint code from composing a refresh-token CAS and its child
/// token inserts as separate, race-prone writes.
#[async_trait]
pub trait OAuthProviderTokenStore: Send + Sync {
    async fn find_oauth_access_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError>;

    async fn find_oauth_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderRefreshToken>, AuthError>;

    async fn issue_oauth_tokens(&self, issuance: OAuthTokenIssuance) -> Result<(), AuthError>;

    async fn rotate_oauth_refresh_token(
        &self,
        rotation: OAuthRefreshRotation,
    ) -> Result<OAuthRefreshRotationOutcome, AuthError>;

    async fn store_oauth_refresh_rotation_replay(
        &self,
        refresh_id: Uuid,
        response: String,
    ) -> Result<bool, AuthError>;

    async fn delete_oauth_access_token(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError>;

    async fn revoke_oauth_refresh_token(
        &self,
        id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, AuthError>;

    async fn revoke_oauth_refresh_family(
        &self,
        client_id: &str,
        user_id: Uuid,
    ) -> Result<OAuthTokenRevocationCount, AuthError>;

    async fn revoke_oauth_tokens_for_authorization_code(
        &self,
        authorization_code_id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError>;

    async fn revoke_oauth_tokens_for_session(
        &self,
        session_id: Uuid,
        revoked_at: DateTime<Utc>,
        preserve_offline_access: bool,
    ) -> Result<OAuthTokenRevocationCount, AuthError>;

    async fn prepare_oauth_session_logout(
        &self,
        session_id: Uuid,
    ) -> Result<OAuthSessionLogoutPlan, AuthError>;

    async fn apply_oauth_session_logout(
        &self,
        plan: &OAuthSessionLogoutPlan,
        revoked_at: DateTime<Utc>,
    ) -> Result<OAuthTokenRevocationCount, AuthError>;
}

#[async_trait]
pub trait OAuthProviderAssertionStore: Send + Sync {
    /// Atomically reserves an assertion digest. `false` means it was already
    /// present and the assertion is a replay.
    async fn reserve_oauth_client_assertion(
        &self,
        assertion: OAuthProviderClientAssertion,
    ) -> Result<bool, AuthError>;

    async fn delete_expired_oauth_client_assertions(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, AuthError>;
}

pub trait OAuthProviderStore:
    OAuthProviderClientStore
    + OAuthProviderResourceStore
    + OAuthProviderConsentStore
    + OAuthProviderTokenStore
    + OAuthProviderAssertionStore
    + Send
    + Sync
{
}

impl<T> OAuthProviderStore for T where
    T: OAuthProviderClientStore
        + OAuthProviderResourceStore
        + OAuthProviderConsentStore
        + OAuthProviderTokenStore
        + OAuthProviderAssertionStore
        + Send
        + Sync
{
}
