use super::MemoryStore;
use crate::{AuthError, OperatorSecurityStore};
use async_trait::async_trait;
use chrono::Utc;

#[async_trait]
impl OperatorSecurityStore for MemoryStore {
    async fn is_temporary_password(&self, user_id: &str) -> Result<bool, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .temporary_passwords
            .contains(user_id))
    }

    async fn set_temporary_password(
        &self,
        user_id: &str,
        temporary: bool,
    ) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        if temporary {
            if !state.users.contains_key(user_id) {
                return Err(AuthError::NotFound);
            }
            state.temporary_passwords.insert(user_id.to_owned());
        } else {
            state.temporary_passwords.remove(user_id);
        }
        Ok(())
    }

    async fn recover_sole_owner(
        &self,
        user_id: &str,
        owner_role: &str,
        password_hash: String,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let owners: Vec<_> = state
            .users
            .values()
            .filter(|user| !user.is_anonymous && user.role == owner_role)
            .map(|user| user.id.clone())
            .collect();
        if owners.len() != 1 || owners[0] != user_id {
            return Ok(false);
        }
        let Some(user) = state.users.get_mut(user_id) else {
            return Ok(false);
        };
        user.banned = false;
        user.ban_reason = None;
        user.ban_expires = None;
        user.updated_at = Utc::now();
        state.passwords.insert(user_id.to_owned(), password_hash);
        state
            .sessions
            .retain(|_, session| session.user_id != user_id);
        state
            .passkeys
            .retain(|_, passkey| passkey.user_id != user_id);
        state.api_keys.retain(|_, key| key.reference_id != user_id);
        state.temporary_passwords.insert(user_id.to_owned());
        Ok(true)
    }
}
