use super::{AuthService, SignInResult, user::validate_admin_roles};
use crate::{
    AdminListUsersQuery, AdminPermissionSet, AdminUserUpdate, AuthError, AuthSession, AuthUser,
    SessionWithUser,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

impl AuthService {
    pub async fn list_users(
        &self,
        actor: &SessionWithUser,
        query: AdminListUsersQuery,
    ) -> Result<(Vec<AuthUser>, i64), AuthError> {
        self.require_admin_permission(actor, "user", &["list"])
            .await?;
        let users = self.store.list_users(&query).await?;
        let total = self.store.count_users(&query.conditions).await?;
        Ok((users, total))
    }

    pub async fn admin_get_user(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
    ) -> Result<AuthUser, AuthError> {
        self.require_admin_permission(actor, "user", &["get"])
            .await?;
        self.store
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| crate::AdminError::UserNotFound.into())
    }

    pub async fn admin_has_permission(
        &self,
        actor: &SessionWithUser,
        _user_id: Option<Uuid>,
        _role: Option<&str>,
        permissions: &AdminPermissionSet,
    ) -> Result<bool, AuthError> {
        Ok(self
            .config
            .admin
            .authorizes(actor.user.id, &actor.user.role, permissions))
    }

    pub async fn admin_update_user(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        update: AdminUserUpdate,
    ) -> Result<AuthUser, AuthError> {
        self.require_admin_permission(actor, "user", &["update"])
            .await?;
        if update.role.is_some() {
            self.require_admin_permission(actor, "user", &["set-role"])
                .await?;
        }
        if update.email.is_some() || update.email_verified.is_some() {
            self.require_admin_permission(actor, "user", &["set-email"])
                .await?;
        }
        if update.banned.is_some() || update.ban_reason.is_some() || update.ban_expires.is_some() {
            self.require_admin_permission(actor, "user", &["ban"])
                .await?;
        }
        if update.banned == Some(true) && actor.user.id == user_id {
            return Err(crate::AdminError::CannotBanSelf.into());
        }
        if let Some(role) = &update.role {
            validate_admin_roles(&self.config.admin, role)?;
        }
        if let Some(email) = &update.email
            && !super::user::valid_email(email)
        {
            return Err(AuthError::InvalidEmail);
        }
        if let Some(email) = &update.email
            && self
                .store
                .find_user_by_email(email)
                .await?
                .is_some_and(|user| user.id != user_id)
        {
            return Err(crate::AdminError::UserAlreadyExistsEmail.into());
        }
        let banned = update.banned == Some(true);
        let user = self
            .store
            .admin_update_user(user_id, update)
            .await
            .map_err(admin_user_error)?;
        if banned {
            self.store.delete_user_sessions(user_id).await?;
        }
        Ok(user)
    }

    pub async fn set_user_role(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        role: &str,
    ) -> Result<AuthUser, AuthError> {
        self.require_admin_permission(actor, "user", &["set-role"])
            .await?;
        validate_admin_roles(&self.config.admin, role)?;
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(crate::AdminError::UserNotFound)?;
        if target.is_anonymous {
            return Err(AuthError::Forbidden);
        }
        self.protect_final_owner(&target, role != "owner").await?;
        let updated = self
            .store
            .update_user_role(user_id, role)
            .await
            .map_err(admin_user_error)?;
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
        self.require_admin_permission(actor, "user", &["ban"])
            .await?;
        if actor.user.id == user_id {
            return Err(crate::AdminError::CannotBanSelf.into());
        }
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(crate::AdminError::UserNotFound)?;
        self.protect_final_owner(&target, true).await?;
        let reason = reason
            .or_else(|| self.config.admin.default_ban_reason.clone())
            .or_else(|| Some("No reason".into()));
        let expires_at = expires_at.or_else(|| {
            self.config
                .admin
                .default_ban_expires_in_seconds
                .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds))
        });
        let updated = self
            .store
            .update_user_ban(user_id, true, reason.clone(), expires_at)
            .await
            .map_err(admin_user_error)?;
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
        self.require_admin_permission(actor, "user", &["ban"])
            .await?;
        let updated = self
            .store
            .update_user_ban(user_id, false, None, None)
            .await
            .map_err(admin_user_error)?;
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
        self.require_admin_permission(actor, "session", &["list"])
            .await?;
        self.store.list_sessions(user_id).await
    }

    pub async fn revoke_user_session(
        &self,
        actor: &SessionWithUser,
        session_id: Uuid,
    ) -> Result<(), AuthError> {
        self.require_admin_permission(actor, "session", &["revoke"])
            .await?;
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
        self.require_admin_permission(actor, "session", &["revoke"])
            .await?;
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
        self.require_admin_permission(actor, "user", &["impersonate"])
            .await?;
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(crate::AdminError::UserNotFound)?;
        if !self.config.admin.allow_impersonating_admins
            && self.config.admin.is_admin_target(target.id, &target.role)
            && !self.config.admin.authorizes(
                actor.user.id,
                &actor.user.role,
                &crate::admin::permission("user", &["impersonate-admins"]),
            )
        {
            return Err(crate::AdminError::CannotImpersonateAdmin.into());
        }
        let expires_at = Utc::now()
            + chrono::Duration::seconds(self.config.admin.impersonation_session_duration_seconds);
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
        actor_session_token: &str,
    ) -> Result<SignInResult, AuthError> {
        let actor_id = session.session.actor_user_id.ok_or(AuthError::Forbidden)?;
        let actor_session = self
            .session(actor_session_token)
            .await?
            .filter(|actor| actor.user.id == actor_id)
            .ok_or(AuthError::InvalidSession)?;
        if account_is_banned(&actor_session.user) {
            return Err(AuthError::Forbidden);
        }
        self.store.delete_session_by_id(session.session.id).await?;
        let result = SignInResult {
            token: actor_session_token.to_owned(),
            session: actor_session,
        };
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

    pub(super) async fn admin_session_user(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        if !user.banned {
            return Ok(user);
        }
        if user
            .ban_expires
            .is_some_and(|expires| expires <= Utc::now())
        {
            return self.store.update_user_ban(user.id, false, None, None).await;
        }
        Err(AuthError::AccountDisabled(
            self.config.admin.banned_user_message.clone(),
        ))
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

pub(super) fn admin_user_error(error: AuthError) -> AuthError {
    match error {
        AuthError::NotFound => crate::AdminError::UserNotFound.into(),
        AuthError::UserAlreadyExistsEmail => crate::AdminError::UserAlreadyExistsEmail.into(),
        error => error,
    }
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
