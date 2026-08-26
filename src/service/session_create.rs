use super::{AuthService, SignInResult};
use crate::{
    AfterAuthEvent, AuthError, AuthSession, AuthUser, AuthenticationMethod, BeforeAuthEvent,
    DatabaseModel, DatabaseRecord, SessionWithUser,
};
use chrono::{DateTime, Utc};
use rand::RngExt;
use uuid::Uuid;

const SESSION_TOKEN_ALPHABET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

impl AuthService {
    pub(super) async fn create_session(
        &self,
        user: AuthUser,
        authentication_method: impl Into<Option<AuthenticationMethod>>,
        actor_user_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.create_session_until(
            user,
            authentication_method,
            actor_user_id,
            None,
            ip_address,
            user_agent,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn create_session_expiring_at(
        &self,
        user: AuthUser,
        authentication_method: impl Into<Option<AuthenticationMethod>>,
        actor_user_id: Option<Uuid>,
        expires_at: DateTime<Utc>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.create_session_with_expiry(
            user,
            authentication_method,
            actor_user_id,
            Some(expires_at),
            false,
            ip_address,
            user_agent,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn create_session_until(
        &self,
        user: AuthUser,
        authentication_method: impl Into<Option<AuthenticationMethod>>,
        actor_user_id: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.create_session_with_expiry(
            user,
            authentication_method,
            actor_user_id,
            expires_at,
            true,
            ip_address,
            user_agent,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_session_with_expiry(
        &self,
        user: AuthUser,
        authentication_method: impl Into<Option<AuthenticationMethod>>,
        actor_user_id: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
        cap_to_session_ttl: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let authentication_method = authentication_method.into();
        let user = self.admin_session_user(user).await?;
        self.plugins
            .before(&BeforeAuthEvent::SessionCreate {
                user: user.clone(),
                authentication_method,
                actor_user_id,
            })
            .await?;
        let token = session_token();
        let now = Utc::now();
        let session = AuthSession {
            id: self.generate_id("session"),
            user_id: user.id,
            token: token.clone(),
            actor_user_id,
            authentication_method,
            expires_at: if cap_to_session_ttl {
                expires_at
                    .unwrap_or(now + self.config.session_ttl)
                    .min(now + self.config.session_ttl)
            } else {
                expires_at.unwrap_or(now + self.config.session_ttl)
            },
            created_at: now,
            updated_at: now,
            ip_address,
            user_agent,
            additional_fields: self
                .create_additional_fields(DatabaseModel::Session, serde_json::Map::new())?,
        };
        let session = match self
            .before_database_create(DatabaseRecord::Session(session))
            .await?
        {
            DatabaseRecord::Session(session) => session,
            _ => unreachable!("database hook model was validated"),
        };
        if self.config.session.storage_mode == crate::SessionStorageMode::Database {
            self.store.delete_expired_sessions(now).await?;
        }
        self.persist_session(&token, &session, &user).await?;
        self.after_database_create(&DatabaseRecord::Session(session.clone()))
            .await?;
        let result = SignInResult {
            token,
            session: SessionWithUser { session, user },
        };
        if let Err(error) = self.plugins.initialize_session(&result.session).await {
            let _ = self
                .delete_session_id_with_hooks(result.session.session.id)
                .await;
            return Err(error);
        }
        self.plugins
            .after(&AfterAuthEvent::SessionCreated {
                session: result.session.clone(),
            })
            .await;
        Ok(result)
    }
}

fn session_token() -> String {
    let mut rng = rand::rng();
    (0..32)
        .map(|_| SESSION_TOKEN_ALPHABET[rng.random_range(0..SESSION_TOKEN_ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_credentials_match_better_auth_generate_id_32() {
        let tokens = (0..128).map(|_| session_token()).collect::<Vec<_>>();
        assert!(tokens.iter().all(|token| token.len() == 32));
        assert!(tokens.iter().all(|token| {
            token
                .bytes()
                .all(|byte| SESSION_TOKEN_ALPHABET.contains(&byte))
        }));
        assert!(tokens.windows(2).any(|pair| pair[0] != pair[1]));
    }
}
