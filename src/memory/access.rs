use super::MemoryStore;
use crate::{AccessStore, AuditEvent, AuthError, AuthSession, AuthUser, GuestGrant};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

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

    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        let user = state.users.remove(&user_id).ok_or(AuthError::NotFound)?;
        if let Some(username) = user.username {
            state.usernames.remove(&username);
        }
        state.emails.remove(&user.email);
        state.passwords.remove(&user_id);
        state
            .passkeys
            .retain(|_, passkey| passkey.user_id != user_id);
        let removed_grants: Vec<_> = state
            .guest_grants
            .values()
            .filter(|grant| grant.created_by == user_id)
            .map(|grant| grant.id)
            .collect();
        state
            .guest_grants
            .retain(|_, grant| grant.created_by != user_id);
        state
            .api_keys
            .retain(|_, api_key| api_key.reference_id != user_id);
        state.sessions.retain(|_, session| {
            session.user_id != user_id
                && session.actor_user_id != Some(user_id)
                && session
                    .guest_grant_id
                    .is_none_or(|grant_id| !removed_grants.contains(&grant_id))
        });
        for event in &mut state.audit_events {
            if event.actor_user_id == Some(user_id) {
                event.actor_user_id = None;
            }
            if event.subject_user_id == Some(user_id) {
                event.subject_user_id = None;
            }
        }
        Ok(())
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

    async fn recover_sole_owner(
        &self,
        user_id: Uuid,
        password_hash: String,
        event: AuditEvent,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let owners: Vec<_> = state
            .users
            .values()
            .filter(|user| !user.is_anonymous && user.role == "owner")
            .map(|user| user.id)
            .collect();
        if owners.as_slice() != [user_id] {
            return Ok(false);
        }
        let Some(user) = state.users.get_mut(&user_id) else {
            return Ok(false);
        };
        user.must_change_password = true;
        user.banned = false;
        user.ban_reason = None;
        user.ban_expires = None;
        user.updated_at = Utc::now();
        state.passwords.insert(user_id, password_hash);
        state
            .sessions
            .retain(|_, session| session.user_id != user_id);
        state
            .passkeys
            .retain(|_, passkey| passkey.user_id != user_id);
        state.recovery_codes.remove(&user_id);
        state.audit_events.push(event);
        Ok(true)
    }
}
