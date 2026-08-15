use crate::{
    AccessStore, AuditEvent, AuthError, AuthSession, AuthStore, AuthUser, GuestGrant, StoredPasskey,
};
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
    guest_grants: HashMap<Uuid, GuestGrant>,
    audit_events: Vec<AuditEvent>,
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

#[async_trait]
impl AccessStore for MemoryStore {
    async fn list_users(&self, limit: usize, offset: usize) -> Result<Vec<AuthUser>, AuthError> {
        let mut users: Vec<_> = self.state.read().await.users.values().cloned().collect();
        users.sort_by_key(|user| user.created_at);
        Ok(users.into_iter().skip(offset).take(limit).collect())
    }

    async fn count_users(&self) -> Result<i64, AuthError> {
        Ok(self.state.read().await.users.len() as i64)
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .users
            .values()
            .filter(|user| user.role == role)
            .count() as i64)
    }

    async fn update_user_role(&self, user_id: Uuid, role: &str) -> Result<AuthUser, AuthError> {
        let mut state = self.state.write().await;
        let user = state.users.get_mut(&user_id).ok_or(AuthError::NotFound)?;
        user.role = role.to_owned();
        user.updated_at = Utc::now();
        Ok(user.clone())
    }

    async fn update_user_ban(
        &self,
        user_id: Uuid,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        let mut state = self.state.write().await;
        let user = state.users.get_mut(&user_id).ok_or(AuthError::NotFound)?;
        user.banned = banned;
        user.ban_reason = reason;
        user.ban_expires = expires_at;
        user.updated_at = Utc::now();
        Ok(user.clone())
    }

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<AuthSession>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .sessions
            .values()
            .filter(|session| session.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_session_by_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .sessions
            .retain(|_, session| session.id != session_id);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .sessions
            .retain(|_, session| session.user_id != user_id);
        Ok(())
    }

    async fn create_guest_grant(&self, grant: GuestGrant) -> Result<GuestGrant, AuthError> {
        self.state
            .write()
            .await
            .guest_grants
            .insert(grant.id, grant.clone());
        Ok(grant)
    }

    async fn consume_guest_grant(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<GuestGrant>, AuthError> {
        let mut state = self.state.write().await;
        let grant = state.guest_grants.values_mut().find(|grant| {
            grant.token_hash.as_deref() == Some(token_hash)
                && grant.revoked_at.is_none()
                && grant.valid_from <= now
                && grant.expires_at > now
                && grant.max_uses.is_none_or(|max| grant.uses < max)
        });
        Ok(grant.map(|grant| {
            grant.uses += 1;
            grant.clone()
        }))
    }

    async fn find_guest_grant(&self, grant_id: Uuid) -> Result<Option<GuestGrant>, AuthError> {
        Ok(self.state.read().await.guest_grants.get(&grant_id).cloned())
    }

    async fn list_guest_grants(&self) -> Result<Vec<GuestGrant>, AuthError> {
        let mut grants: Vec<_> = self
            .state
            .read()
            .await
            .guest_grants
            .values()
            .cloned()
            .collect();
        grants.sort_by_key(|grant| std::cmp::Reverse(grant.created_at));
        Ok(grants)
    }

    async fn revoke_guest_grant(
        &self,
        grant_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        let grant = state
            .guest_grants
            .get_mut(&grant_id)
            .ok_or(AuthError::NotFound)?;
        grant.revoked_at = Some(revoked_at);
        Ok(())
    }

    async fn append_audit_event(&self, event: AuditEvent) -> Result<(), AuthError> {
        self.state.write().await.audit_events.push(event);
        Ok(())
    }

    async fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .audit_events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect())
    }
}
