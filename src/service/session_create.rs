use super::{AuthService, SignInResult, hash_token, random_token};
use crate::{
    AfterAuthEvent, AuthError, AuthSession, AuthUser, AuthenticationMethod, BeforeAuthEvent,
    DatabaseModel, DatabaseRecord, SessionWithUser,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

impl AuthService {
    pub(super) async fn create_session(
        &self,
        user: AuthUser,
        authentication_method: AuthenticationMethod,
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
    pub(super) async fn create_session_until(
        &self,
        user: AuthUser,
        authentication_method: AuthenticationMethod,
        actor_user_id: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let user = self.admin_session_user(user).await?;
        self.plugins
            .before(&BeforeAuthEvent::SessionCreate {
                user: user.clone(),
                authentication_method,
                actor_user_id,
            })
            .await?;
        let token = random_token();
        let now = Utc::now();
        let session = AuthSession {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: hash_token(&token),
            actor_user_id,
            authentication_method,
            expires_at: expires_at
                .unwrap_or(now + self.config.session_ttl)
                .min(now + self.config.session_ttl),
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
        self.store.delete_expired_sessions(now).await?;
        self.store.create_session(session.clone()).await?;
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
