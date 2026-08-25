use super::AuthService;
use crate::{AfterAuthEvent, AuditEvent, AuditPlugin, AuthActivity, AuthError, SessionWithUser};

impl AuthService {
    pub async fn list_audit_events(
        &self,
        actor: &SessionWithUser,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, AuthError> {
        self.plugins
            .authorize_sensitive(&crate::SensitiveOperation {
                session: actor,
                operation: "audit.list",
            })
            .await?;
        let plugin = self
            .plugins
            .find::<AuditPlugin>()
            .ok_or(AuthError::NotFound)?;
        plugin.store.list_audit_events(limit.clamp(1, 200)).await
    }

    pub(super) async fn activity(&self, activity: AuthActivity) {
        self.plugins
            .after(&AfterAuthEvent::Activity { activity })
            .await;
    }
}
