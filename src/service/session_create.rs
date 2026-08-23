use super::{AuthService, SignInResult, hash_token, random_token};
use crate::{
    AfterAuthEvent, Assurance, AuthError, AuthSession, AuthUser, BeforeAuthEvent, SessionWithUser,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

impl AuthService {
    pub(super) async fn create_session(
        &self,
        user: AuthUser,
        assurance: Assurance,
        actor_user_id: Option<Uuid>,
        guest_grant_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.create_session_until(
            user,
            assurance,
            actor_user_id,
            guest_grant_id,
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
        assurance: Assurance,
        actor_user_id: Option<Uuid>,
        guest_grant_id: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.plugins
            .before(&BeforeAuthEvent::SessionCreate {
                user: user.clone(),
                assurance,
                actor_user_id,
                guest_grant_id,
            })
            .await?;
        let token = random_token();
        let now = Utc::now();
        let session = AuthSession {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: hash_token(&token),
            actor_user_id,
            guest_grant_id,
            assurance,
            expires_at: expires_at
                .unwrap_or(now + self.config.session_ttl)
                .min(now + self.config.session_ttl),
            created_at: now,
            updated_at: now,
            ip_address,
            user_agent,
        };
        self.store.delete_expired_sessions(now).await?;
        self.store.create_session(session.clone()).await?;
        let result = SignInResult {
            token,
            session: SessionWithUser { session, user },
            mfa_setup_required: false,
        };
        self.plugins
            .after(&AfterAuthEvent::SessionCreated {
                session: result.session.clone(),
            })
            .await;
        Ok(result)
    }
}
