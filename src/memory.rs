use crate::{
    ApiKey, AuthError, AuthSession, AuthStore, AuthUser, GuestGrant, OAuthAccount,
    PasskeyDeleteOutcome, StoredPasskey, VerificationValue,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;

mod access;
mod api_key;
mod guest_capability;
mod jwt;
mod oauth;
mod operator_security;
mod phone_number;
mod security;
mod session;
mod siwe;
mod user;
mod verification;

#[derive(Default)]
struct MemoryState {
    users: HashMap<Uuid, AuthUser>,
    usernames: HashMap<String, Uuid>,
    emails: HashMap<String, Uuid>,
    phone_numbers: HashMap<String, Uuid>,
    wallet_addresses: HashMap<(String, u64), crate::WalletAddress>,
    passwords: HashMap<Uuid, String>,
    oauth_accounts: HashMap<(String, String), OAuthAccount>,
    sessions: HashMap<String, AuthSession>,
    passkeys: HashMap<Uuid, StoredPasskey>,
    guest_grants: HashMap<Uuid, GuestGrant>,
    guest_sessions: HashMap<Uuid, Uuid>,
    api_keys: HashMap<Uuid, ApiKey>,
    rate_limits: HashMap<String, RateLimitWindow>,
    temporary_passwords: HashSet<Uuid>,
    verifications: HashMap<Uuid, VerificationValue>,
    jwks: Vec<crate::StoredJwk>,
}

struct RateLimitWindow {
    count: u32,
    last_request: DateTime<Utc>,
}

/// In-memory adapter for tests and explicitly non-persistent development use.
#[derive(Clone, Default)]
pub struct MemoryStore {
    state: Arc<RwLock<MemoryState>>,
}

#[async_trait]
impl AuthStore for MemoryStore {
    fn bind_schema(&self, _schema: Arc<crate::AuthSchemaCatalog>) -> Result<(), AuthError> {
        Ok(())
    }

    fn jwk_store(&self) -> Option<&dyn crate::JwkStore> {
        Some(self)
    }

    async fn create_password_user(
        &self,
        user: AuthUser,
        credential_account: crate::OAuthAccount,
    ) -> Result<AuthUser, AuthError> {
        user::create_password(self, user, credential_account).await
    }

    async fn upsert_password_user(
        &self,
        user: AuthUser,
        credential_account: crate::OAuthAccount,
    ) -> Result<AuthUser, AuthError> {
        user::upsert_password(self, user, credential_account).await
    }

    async fn create_anonymous_user(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        user::create_without_account(self, user).await
    }

    async fn create_user_without_account(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        user::create_without_account(self, user).await
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError> {
        user::find_by_username(self, username).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        user::find_by_email(self, email).await
    }

    async fn update_user_profile(
        &self,
        user_id: Uuid,
        update: crate::UserProfileUpdate,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::update_profile(self, user_id, update).await
    }

    async fn update_user_email(
        &self,
        user_id: Uuid,
        expected_email: &str,
        new_email: &str,
        email_verified: bool,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::update_email(self, user_id, expected_email, new_email, email_verified).await
    }

    async fn promote_email_owner(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::promote_email_owner(self, user_id, now).await
    }

    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        user::find_password_hash(self, user_id).await
    }

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError> {
        user::update_password_hash(self, user_id, password_hash).await
    }

    async fn set_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError> {
        user::set_password_hash(self, user_id, password_hash).await
    }

    async fn save_passkey(&self, passkey: StoredPasskey) -> Result<StoredPasskey, AuthError> {
        let mut state = self.state.write().await;
        if state
            .passkeys
            .values()
            .any(|stored| stored.credential_id == passkey.credential_id)
        {
            return Err(AuthError::CredentialAlreadyRegistered);
        }
        state.passkeys.insert(passkey.id, passkey.clone());
        Ok(passkey)
    }

    async fn list_passkeys(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .passkeys
            .values()
            .filter(|passkey| passkey.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .passkeys
            .values()
            .find(|passkey| passkey.credential_id == credential_id)
            .cloned())
    }

    async fn find_passkey_by_id(
        &self,
        passkey_id: Uuid,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        Ok(self.state.read().await.passkeys.get(&passkey_id).cloned())
    }

    async fn update_passkey_after_authentication(
        &self,
        passkey: StoredPasskey,
        expected_counter: u32,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let Some(current) = state.passkeys.get(&passkey.id) else {
            return Ok(false);
        };
        if current.counter != expected_counter {
            return Ok(false);
        }
        state.passkeys.insert(passkey.id, passkey);
        Ok(true)
    }

    async fn update_passkey_name(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        let mut state = self.state.write().await;
        let Some(passkey) = state
            .passkeys
            .get_mut(&passkey_id)
            .filter(|passkey| passkey.user_id == user_id)
        else {
            return Ok(None);
        };
        passkey.name = Some(name);
        Ok(Some(passkey.clone()))
    }

    async fn delete_passkey(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        minimum_remaining: usize,
    ) -> Result<PasskeyDeleteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let owned = state
            .passkeys
            .get(&passkey_id)
            .is_some_and(|passkey| passkey.user_id == user_id);
        if !owned {
            return Ok(PasskeyDeleteOutcome::NotFound);
        }
        let count = state
            .passkeys
            .values()
            .filter(|passkey| passkey.user_id == user_id)
            .count();
        if count <= minimum_remaining {
            return Ok(PasskeyDeleteOutcome::MinimumRequired);
        }
        state.passkeys.remove(&passkey_id);
        let remaining = count - 1;
        Ok(PasskeyDeleteOutcome::Deleted { remaining })
    }

    async fn delete_user_passkeys(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .passkeys
            .retain(|_, passkey| passkey.user_id != user_id);
        Ok(())
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<AuthUser>, AuthError> {
        user::find_by_id(self, user_id).await
    }

    async fn create_session(&self, session: AuthSession) -> Result<(), AuthError> {
        session::create(self, session).await
    }

    async fn find_session(
        &self,
        token: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
        session::find(self, token).await
    }

    async fn find_session_by_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError> {
        session::find_by_id(self, session_id).await
    }

    async fn update_session_fields(
        &self,
        session_id: Uuid,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<AuthSession>, AuthError> {
        session::update_fields(self, session_id, fields).await
    }

    async fn refresh_session(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AuthSession>, AuthError> {
        session::refresh(self, token, expires_at, updated_at).await
    }

    async fn delete_session(&self, token: &str) -> Result<(), AuthError> {
        session::delete(self, token).await
    }

    async fn expire_session(
        &self,
        session_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        session::expire(self, session_id, expires_at).await
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        session::delete_expired(self, now).await
    }
}
