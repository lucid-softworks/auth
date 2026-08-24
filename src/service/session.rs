use super::AuthService;
use crate::{AuthError, AuthSession, SessionWithUser};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

impl AuthService {
    pub async fn list_current_sessions(
        &self,
        actor: &SessionWithUser,
    ) -> Result<Vec<AuthSession>, AuthError> {
        require_account_session(actor)?;
        self.store.list_sessions(actor.user.id).await
    }

    pub async fn revoke_current_user_session(
        &self,
        actor: &SessionWithUser,
        session_id: Uuid,
    ) -> Result<(), AuthError> {
        require_account_session(actor)?;
        let owned = self
            .store
            .list_sessions(actor.user.id)
            .await?
            .into_iter()
            .any(|session| session.id == session_id && session.expires_at > Utc::now());
        if owned {
            self.delete_session_id_with_hooks(session_id).await?;
            self.audit(
                actor.user.id,
                Some(actor.user.id),
                "session.revoked",
                Some(session_id.to_string()),
                json!({ "selfService": true }),
            )
            .await;
        }
        Ok(())
    }

    pub async fn revoke_other_sessions(&self, actor: &SessionWithUser) -> Result<(), AuthError> {
        require_account_session(actor)?;
        let sessions = self.store.list_sessions(actor.user.id).await?;
        for session in sessions {
            if session.id != actor.session.id {
                self.delete_session_id_with_hooks(session.id).await?;
            }
        }
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "session.others_revoked",
            Some(actor.session.id.to_string()),
            json!({}),
        )
        .await;
        Ok(())
    }

    pub async fn revoke_all_current_user_sessions(
        &self,
        actor: &SessionWithUser,
    ) -> Result<(), AuthError> {
        require_account_session(actor)?;
        self.delete_user_sessions_with_hooks(actor.user.id).await?;
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "session.all_revoked",
            None,
            json!({}),
        )
        .await;
        Ok(())
    }
}

fn require_account_session(session: &SessionWithUser) -> Result<(), AuthError> {
    if session.user.is_anonymous || session.session.actor_user_id.is_some() {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

pub(super) fn random_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore, NewPasswordUser};
    use std::sync::Arc;

    #[tokio::test]
    async fn revokes_every_session_except_the_current_one() {
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([43_u8; 32]).unwrap(),
        );
        service
            .provision_password_user(NewPasswordUser {
                username: "luna".into(),
                name: "Luna".into(),
                email: None,
                password: "password".into(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        let current = service
            .sign_in_username("luna", "password".into(), None, None)
            .await
            .unwrap();
        let other = service
            .sign_in_username("luna", "password".into(), None, None)
            .await
            .unwrap();

        service
            .revoke_other_sessions(&current.session)
            .await
            .unwrap();

        assert!(service.session(&current.token).await.unwrap().is_some());
        assert!(service.session(&other.token).await.unwrap().is_none());
    }
}
