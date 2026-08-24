use super::AuthService;
use crate::{AuthError, MultiSessionConfig, MultiSessionPlugin, SessionWithUser};
use chrono::Utc;

impl AuthService {
    pub(crate) fn multi_session_config(&self) -> Option<&MultiSessionConfig> {
        self.plugins
            .find::<MultiSessionPlugin>()
            .map(MultiSessionPlugin::config)
    }

    pub(crate) async fn multi_session_stored(
        &self,
        token: &str,
    ) -> Result<Option<SessionWithUser>, AuthError> {
        self.find_stored_session(token).await
    }

    pub(crate) async fn multi_session_delete(&self, token: &str) -> Result<(), AuthError> {
        self.delete_session_token_with_hooks(token).await
    }

    pub(crate) async fn multi_session_list(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> Result<Vec<SessionWithUser>, AuthError> {
        let now = Utc::now();
        let mut sessions = Vec::new();
        for token in tokens {
            let Some(session) = self.find_stored_session(token).await? else {
                continue;
            };
            if only_active && session.session.expires_at <= now {
                continue;
            }
            sessions.push(session);
        }
        Ok(sessions)
    }
}
