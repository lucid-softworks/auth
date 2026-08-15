use crate::{AuthError, AuthSession, AuthStore, AuthUser, StoredPasskey};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Default)]
struct MemoryState {
    users: HashMap<Uuid, AuthUser>,
    usernames: HashMap<String, Uuid>,
    passwords: HashMap<Uuid, String>,
    sessions: HashMap<String, AuthSession>,
    passkeys: HashMap<Uuid, StoredPasskey>,
}

/// In-memory adapter for tests and explicitly non-persistent development use.
#[derive(Clone, Default)]
pub struct MemoryStore {
    state: Arc<RwLock<MemoryState>>,
}

#[async_trait]
impl AuthStore for MemoryStore {
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
            let existing = state
                .users
                .get_mut(&id)
                .ok_or_else(|| AuthError::Storage("username index is inconsistent".into()))?;
            existing.name = user.name;
            existing.email = user.email;
            existing.role = user.role;
            existing.updated_at = user.updated_at;
            existing.clone()
        } else {
            state.usernames.insert(username, user.id);
            state.users.insert(user.id, user.clone());
            user
        };
        state.passwords.insert(stored.id, password_hash);
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
