use super::AuthService;
use crate::SessionWithUser;

impl AuthService {
    pub(crate) async fn session_being_bound(&self, token: &str) -> Option<SessionWithUser> {
        let observed_by_one_time_token = self
            .plugins
            .find::<crate::OneTimeTokenPlugin>()
            .is_some_and(|plugin| plugin.config().set_ott_header_on_new_session);
        let observed_by_electron = self.plugins.find::<crate::ElectronPlugin>().is_some();
        if !observed_by_one_time_token && !observed_by_electron {
            return None;
        }
        if let Ok(Some(session)) = self.find_stored_session(token).await {
            return Some(session);
        }
        self.pending_stateless_sessions
            .lock()
            .await
            .get(token)
            .cloned()
    }
}
