use super::AuthService;
use crate::{AuthError, PluginSession};

impl AuthService {
    pub(crate) async fn plugin_session(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<PluginSession>, AuthError> {
        let Some(mut plugin_session) = self.plugins.session_from_headers(self, headers).await?
        else {
            return Ok(None);
        };
        plugin_session.session.user = self.admin_session_user(plugin_session.session.user).await?;
        if !self
            .plugins
            .validates_session(&plugin_session.session)
            .await?
        {
            return Ok(None);
        }
        self.plugins
            .authorize_application_access(&plugin_session.session)
            .await?;
        Ok(Some(plugin_session))
    }
}
