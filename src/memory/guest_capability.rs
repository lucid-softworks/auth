use super::MemoryStore;
use crate::{AuthError, GuestCapabilityStore, GuestGrant};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
impl GuestCapabilityStore for MemoryStore {
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

    async fn attach_guest_session(
        &self,
        grant_id: Uuid,
        session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let active = state.guest_grants.get(&grant_id).is_some_and(|grant| {
            grant.revoked_at.is_none() && grant.valid_from <= now && grant.expires_at > now
        });
        if !active
            || !state
                .sessions
                .values()
                .any(|session| session.id == session_id)
        {
            return Ok(false);
        }
        state.guest_sessions.insert(session_id.to_owned(), grant_id);
        Ok(true)
    }

    async fn find_guest_grant_for_session(
        &self,
        session_id: &str,
    ) -> Result<Option<GuestGrant>, AuthError> {
        let state = self.state.read().await;
        Ok(state
            .guest_sessions
            .get(session_id)
            .and_then(|grant_id| state.guest_grants.get(grant_id))
            .cloned())
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
        grant.token_hash = None;
        let session_ids: Vec<_> = state
            .guest_sessions
            .iter()
            .filter(|(_, attached)| **attached == grant_id)
            .map(|(session_id, _)| session_id.clone())
            .collect();
        state
            .sessions
            .retain(|_, session| !session_ids.contains(&session.id));
        state
            .guest_sessions
            .retain(|_, attached| *attached != grant_id);
        Ok(())
    }
}
