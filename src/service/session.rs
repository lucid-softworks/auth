use super::AuthService;
use crate::{AuthError, AuthSession, SessionWithUser};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngExt;
use sha2::{Digest, Sha256};

impl AuthService {
    pub async fn list_current_sessions(
        &self,
        actor: &SessionWithUser,
    ) -> Result<Vec<AuthSession>, AuthError> {
        require_account_session(actor)?;
        Ok(self
            .stored_sessions(&actor.user.id)
            .await?
            .into_iter()
            .map(|(_, session)| session)
            .collect())
    }

    pub async fn revoke_current_user_session(
        &self,
        actor: &SessionWithUser,
        session_id: &str,
    ) -> Result<(), AuthError> {
        require_account_session(actor)?;
        let owned = self
            .store
            .list_sessions(&actor.user.id)
            .await?
            .into_iter()
            .any(|session| session.id == session_id && session.expires_at > Utc::now());
        if owned {
            self.delete_session_id_with_hooks(session_id).await?;
            self.activity(crate::AuthActivity::SessionRevoked {
                actor_user_id: actor.user.id.clone(),
                subject_user_id: Some(actor.user.id.clone()),
                session_id: Some(session_id.to_owned()),
                self_service: true,
            })
            .await;
        }
        Ok(())
    }

    pub async fn revoke_current_user_session_token(
        &self,
        actor: &SessionWithUser,
        token: &str,
    ) -> Result<(), AuthError> {
        require_account_session(actor)?;
        let owned = self
            .stored_sessions(&actor.user.id)
            .await?
            .into_iter()
            .any(|(candidate, session)| candidate == token && session.expires_at > Utc::now());
        if owned {
            let session_id = self
                .find_stored_session(token)
                .await?
                .map(|session| session.session.id);
            self.delete_session_token_with_hooks(token).await?;
            self.activity(crate::AuthActivity::SessionRevoked {
                actor_user_id: actor.user.id.clone(),
                subject_user_id: Some(actor.user.id.clone()),
                session_id,
                self_service: true,
            })
            .await;
        }
        Ok(())
    }

    pub async fn revoke_other_sessions(&self, actor: &SessionWithUser) -> Result<(), AuthError> {
        require_account_session(actor)?;
        let sessions = self.stored_sessions(&actor.user.id).await?;
        for (_, session) in sessions {
            if session.id != actor.session.id {
                self.delete_session_id_with_hooks(&session.id).await?;
            }
        }
        self.activity(crate::AuthActivity::OtherSessionsRevoked {
            user_id: actor.user.id.clone(),
            retained_session_id: actor.session.id.clone(),
        })
        .await;
        Ok(())
    }

    pub async fn revoke_all_current_user_sessions(
        &self,
        actor: &SessionWithUser,
    ) -> Result<(), AuthError> {
        require_account_session(actor)?;
        self.delete_user_sessions_with_hooks(&actor.user.id).await?;
        self.activity(crate::AuthActivity::AllSessionsRevoked {
            user_id: actor.user.id.clone(),
        })
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

    #[test]
    fn non_core_callers_keep_the_existing_url_safe_random_token() {
        let token = random_token();
        assert_eq!(token.len(), 43);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

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
