use crate::{
    ApiKey, AuditEvent, AuthError, AuthSession, AuthStore, AuthUser, GuestGrant,
    PasskeyDeleteOutcome, StoredPasskey,
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
mod security;

#[derive(Default)]
struct MemoryState {
    users: HashMap<Uuid, AuthUser>,
    usernames: HashMap<String, Uuid>,
    passwords: HashMap<Uuid, String>,
    sessions: HashMap<String, AuthSession>,
    passkeys: HashMap<Uuid, StoredPasskey>,
    guest_grants: HashMap<Uuid, GuestGrant>,
    api_keys: HashMap<Uuid, ApiKey>,
    audit_events: Vec<AuditEvent>,
    rate_limits: HashMap<String, RateLimitWindow>,
    recovery_codes: HashMap<Uuid, HashSet<String>>,
}

struct RateLimitWindow {
    attempts: usize,
    expires_at: DateTime<Utc>,
}

/// In-memory adapter for tests and explicitly non-persistent development use.
#[derive(Clone, Default)]
pub struct MemoryStore {
    state: Arc<RwLock<MemoryState>>,
}

#[async_trait]
impl AuthStore for MemoryStore {
    async fn create_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        let username = user
            .username
            .as_ref()
            .ok_or_else(|| AuthError::Storage("password user requires a username".into()))?;
        let mut state = self.state.write().await;
        if state.usernames.contains_key(username)
            || state
                .users
                .values()
                .any(|stored| stored.email == user.email)
        {
            return Err(AuthError::UserAlreadyExists);
        }
        state.usernames.insert(username.clone(), user.id);
        state.passwords.insert(user.id, password_hash);
        state.users.insert(user.id, user.clone());
        Ok(user)
    }

    async fn upsert_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        let username = user
            .username
            .as_deref()
            .ok_or_else(|| AuthError::Storage("password user requires a username".into()))?
            .to_owned();
        let mut state = self.state.write().await;
        let existing_id = state.usernames.get(&username).copied();
        let stored = if let Some(id) = existing_id {
            let configured_hash_is_active = state
                .passwords
                .get(&id)
                .is_some_and(|stored| stored == &password_hash);
            let existing = state
                .users
                .get_mut(&id)
                .ok_or_else(|| AuthError::Storage("username index is inconsistent".into()))?;
            existing.name = user.name;
            existing.email = user.email;
            existing.role = user.role;
            if user.must_change_password && configured_hash_is_active {
                existing.must_change_password = true;
            }
            existing.updated_at = user.updated_at;
            existing.clone()
        } else {
            state.usernames.insert(username, user.id);
            state.users.insert(user.id, user.clone());
            user
        };
        state.passwords.entry(stored.id).or_insert(password_hash);
        Ok(stored)
    }

    async fn create_anonymous_user(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        self.state.write().await.users.insert(user.id, user.clone());
        Ok(user)
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError> {
        let state = self.state.read().await;
        Ok(state
            .usernames
            .get(username)
            .and_then(|id| state.users.get(id))
            .cloned())
    }

    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        Ok(self.state.read().await.passwords.get(&user_id).cloned())
    }

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        let stored = state
            .passwords
            .get_mut(&user_id)
            .ok_or(AuthError::CredentialAccountNotFound)?;
        *stored = password_hash;
        if let Some(user) = state.users.get_mut(&user_id) {
            user.must_change_password = false;
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn set_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        if !state.users.contains_key(&user_id) {
            return Err(AuthError::NotFound);
        }
        state.passwords.insert(user_id, password_hash);
        if let Some(user) = state.users.get_mut(&user_id) {
            user.must_change_password = true;
            user.updated_at = Utc::now();
        }
        Ok(())
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

    async fn list_all_passkeys(&self) -> Result<Vec<StoredPasskey>, AuthError> {
        Ok(self.state.read().await.passkeys.values().cloned().collect())
    }

    async fn update_passkey(&self, passkey: StoredPasskey) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .passkeys
            .insert(passkey.id, passkey);
        Ok(())
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
        passkey.updated_at = Utc::now();
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
        if remaining == 0 {
            state.recovery_codes.remove(&user_id);
        }
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
        Ok(self.state.read().await.users.get(&user_id).cloned())
    }

    async fn create_session(&self, session: AuthSession) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .sessions
            .insert(session.token_hash.clone(), session);
        Ok(())
    }

    async fn find_session(
        &self,
        token_hash: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
        let state = self.state.read().await;
        let Some(session) = state.sessions.get(token_hash).cloned() else {
            return Ok(None);
        };
        Ok(state
            .users
            .get(&session.user_id)
            .cloned()
            .map(|user| (session, user)))
    }

    async fn delete_session(&self, token_hash: &str) -> Result<(), AuthError> {
        self.state.write().await.sessions.remove(token_hash);
        Ok(())
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .sessions
            .retain(|_, session| session.expires_at > now);
        Ok(())
    }
}
