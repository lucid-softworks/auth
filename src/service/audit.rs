use super::{AuthService, access::require_owner};
use crate::{AuditEvent, AuditMetadata, AuditOutcome, AuditPlugin, AuthError, SessionWithUser};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

impl AuthService {
    pub async fn list_audit_events(
        &self,
        actor: &SessionWithUser,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, AuthError> {
        require_owner(actor)?;
        let plugin = self
            .plugins
            .find::<AuditPlugin>()
            .ok_or(AuthError::NotFound)?;
        plugin.store.list_audit_events(limit.clamp(1, 200)).await
    }

    pub(super) async fn audit(
        &self,
        actor_user_id: Uuid,
        subject_user_id: Option<Uuid>,
        action: &str,
        target: Option<String>,
        metadata: Value,
    ) {
        self.record_audit_event(
            Some(actor_user_id),
            subject_user_id,
            action,
            target,
            metadata,
        )
        .await;
    }

    pub(super) async fn audit_actorless(
        &self,
        subject_user_id: Option<Uuid>,
        action: &str,
        target: Option<String>,
        metadata: Value,
    ) {
        self.record_audit_event(None, subject_user_id, action, target, metadata)
            .await;
    }

    async fn record_audit_event(
        &self,
        actor_user_id: Option<Uuid>,
        subject_user_id: Option<Uuid>,
        action: &str,
        target: Option<String>,
        metadata: Value,
    ) {
        let Some(plugin) = self.plugins.find::<AuditPlugin>() else {
            return;
        };
        let Ok(metadata) = AuditMetadata::new(metadata) else {
            return;
        };
        let _ = plugin
            .store
            .record_audit_event(
                AuditEvent {
                    id: Uuid::new_v4(),
                    actor_user_id,
                    subject_user_id,
                    action: action.to_owned(),
                    target,
                    outcome: AuditOutcome::Success,
                    metadata,
                    created_at: Utc::now(),
                },
                plugin.max_events,
            )
            .await;
    }
}
