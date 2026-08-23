use super::{AuthService, SignInResult, user::validate_managed_role};
use crate::{
    AuditEvent, AuditMetadata, AuditOutcome, AuditPlugin, AuthError, AuthSession, AuthUser,
    SessionWithUser,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

impl AuthService {
    pub async fn list_users(
        &self,
        actor: &SessionWithUser,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<AuthUser>, i64), AuthError> {
        self.require_recent_owner(actor).await?;
        let limit = limit.clamp(1, 100);
        let users = self.store.list_users(limit, offset).await?;
        let total = self.store.count_users().await?;
        Ok((users, total))
    }

    pub async fn set_user_role(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        role: &str,
    ) -> Result<AuthUser, AuthError> {
        self.require_recent_owner(actor).await?;
        validate_managed_role(role)?;
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if target.is_anonymous {
            return Err(AuthError::Forbidden);
        }
        self.protect_final_owner(&target, role != "owner").await?;
        let updated = self.store.update_user_role(user_id, role).await?;
        if role == "owner" && target.role != "owner" {
            self.store.delete_user_sessions(user_id).await?;
        }
        self.audit(
            actor.user.id,
            Some(user_id),
            "user.role.changed",
            Some(user_id.to_string()),
            json!({ "from": target.role, "to": role }),
        )
        .await;
        Ok(updated)
    }

    pub async fn ban_user(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        self.require_recent_owner(actor).await?;
        if actor.user.id == user_id {
            return Err(AuthError::Forbidden);
        }
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        self.protect_final_owner(&target, true).await?;
        let updated = self
            .store
            .update_user_ban(user_id, true, reason.clone(), expires_at)
            .await?;
        self.store.delete_user_sessions(user_id).await?;
        self.audit(
            actor.user.id,
            Some(user_id),
            "user.banned",
            Some(user_id.to_string()),
            json!({ "reason": reason, "expiresAt": expires_at }),
        )
        .await;
        Ok(updated)
    }

    pub async fn unban_user(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
    ) -> Result<AuthUser, AuthError> {
        self.require_recent_owner(actor).await?;
        let updated = self
            .store
            .update_user_ban(user_id, false, None, None)
            .await?;
        self.audit(
            actor.user.id,
            Some(user_id),
            "user.unbanned",
            Some(user_id.to_string()),
            json!({}),
        )
        .await;
        Ok(updated)
    }

    pub async fn list_user_sessions(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
    ) -> Result<Vec<AuthSession>, AuthError> {
        require_owner(actor)?;
        if self.store.find_user_by_id(user_id).await?.is_none() {
            return Err(AuthError::NotFound);
        }
        self.store.list_sessions(user_id).await
    }

    pub async fn revoke_user_session(
        &self,
        actor: &SessionWithUser,
        session_id: Uuid,
    ) -> Result<(), AuthError> {
        self.require_recent_owner(actor).await?;
        if actor.session.id == session_id {
            return Err(AuthError::Forbidden);
        }
        self.store.delete_session_by_id(session_id).await?;
        self.audit(
            actor.user.id,
            None,
            "session.revoked",
            Some(session_id.to_string()),
            json!({}),
        )
        .await;
        Ok(())
    }

    pub async fn revoke_user_sessions(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        self.require_recent_owner(actor).await?;
        if actor.user.id == user_id {
            return Err(AuthError::Forbidden);
        }
        if self.store.find_user_by_id(user_id).await?.is_none() {
            return Err(AuthError::NotFound);
        }
        self.store.delete_user_sessions(user_id).await?;
        self.audit(
            actor.user.id,
            Some(user_id),
            "session.user_revoked",
            Some(user_id.to_string()),
            json!({}),
        )
        .await;
        Ok(())
    }

    pub async fn impersonate_user(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.require_recent_owner(actor).await?;
        if actor.user.id == user_id {
            return Err(AuthError::Forbidden);
        }
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if target.is_anonymous || target.role == "owner" || account_is_banned(&target) {
            return Err(AuthError::Forbidden);
        }
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let result = self
            .create_session_until(
                target,
                actor.session.authentication_method,
                Some(actor.user.id),
                Some(expires_at),
                ip_address,
                user_agent,
            )
            .await?;
        self.audit(
            actor.user.id,
            Some(user_id),
            "impersonation.started",
            Some(result.session.session.id.to_string()),
            json!({ "expiresAt": result.session.session.expires_at }),
        )
        .await;
        Ok(result)
    }

    pub async fn stop_impersonating(
        &self,
        session: &SessionWithUser,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let actor_id = session.session.actor_user_id.ok_or(AuthError::Forbidden)?;
        let actor = self
            .store
            .find_user_by_id(actor_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if actor.role != "owner" || account_is_banned(&actor) {
            return Err(AuthError::Forbidden);
        }
        self.store.delete_session_by_id(session.session.id).await?;
        let result = self
            .create_session(
                actor,
                session.session.authentication_method,
                None,
                ip_address,
                user_agent,
            )
            .await?;
        self.audit(
            actor_id,
            Some(session.user.id),
            "impersonation.stopped",
            Some(session.session.id.to_string()),
            json!({}),
        )
        .await;
        Ok(result)
    }

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

    pub(super) async fn protect_final_owner(
        &self,
        target: &AuthUser,
        removing_owner: bool,
    ) -> Result<(), AuthError> {
        if removing_owner
            && target.role == "owner"
            && self.store.count_users_by_role("owner").await? <= 1
        {
            return Err(AuthError::LastOwner);
        }
        Ok(())
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

pub(super) fn require_owner(session: &SessionWithUser) -> Result<(), AuthError> {
    if session.user.role != "owner"
        || session.user.is_anonymous
        || session.session.actor_user_id.is_some()
        || account_is_banned(&session.user)
    {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

fn account_is_banned(user: &AuthUser) -> bool {
    user.banned && user.ban_expires.is_none_or(|expires| expires > Utc::now())
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
