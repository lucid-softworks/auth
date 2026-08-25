use super::{AuthService, SignInResult, user::validate_admin_roles};
use crate::{
    AdminListUsersQuery, AdminPermissionSet, AuthError, AuthSession, AuthUser, SessionWithUser,
};
use chrono::{DateTime, Utc};
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
            .admin_config()?
            .authorizes(actor.user.id, &actor.user.role, permissions))
    }

    pub async fn set_user_role(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        role: &str,
    ) -> Result<AuthUser, AuthError> {
        self.require_admin_permission(actor, "user", &["set-role"])
            .await?;
        validate_admin_roles(self.admin_config()?, role)?;
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(crate::AdminError::UserNotFound)?;
        if target.is_anonymous {
            return Err(AuthError::Forbidden);
        }
        let decision = self
            .plugins
            .authorize_user_management(
                self.store.as_ref(),
                &crate::UserManagementOperation {
                    actor,
                    action: crate::UserManagementAction::ChangeRole {
                        target: &target,
                        new_role: role,
                    },
                },
            )
            .await?;
        let mut candidate = target.clone();
        candidate.role = role.into();
        let candidate = self.prepare_user_update(&target, candidate).await?;
        let updated = self
            .store
            .update_user_role(user_id, &candidate.role)
            .await
            .map_err(admin_user_error)?;
        self.after_database_update(&crate::DatabaseRecord::User(updated.clone()))
            .await?;
        if decision.revoke_target_sessions {
            self.delete_user_sessions_with_hooks(user_id).await?;
        }
        self.activity(crate::AuthActivity::UserRoleChanged {
            actor_user_id: actor.user.id,
            user_id,
            previous_role: target.role,
            new_role: role.to_owned(),
        })
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
        self.plugins
            .authorize_user_management(
                self.store.as_ref(),
                &crate::UserManagementOperation {
                    actor,
                    action: crate::UserManagementAction::ChangeBan {
                        target: &target,
                        banned: true,
                    },
                },
            )
            .await?;
        let admin = self.admin_config()?;
        let reason = reason
            .or_else(|| admin.default_ban_reason.clone())
            .or_else(|| Some("No reason".into()));
        let expires_at = expires_at.or_else(|| {
            admin
                .default_ban_expires_in_seconds
                .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds))
        });
        let mut candidate = target.clone();
        candidate.banned = true;
        candidate.ban_reason.clone_from(&reason);
        candidate.ban_expires = expires_at;
        let candidate = self.prepare_user_update(&target, candidate).await?;
        let updated = self
            .store
            .update_user_ban(
                user_id,
                candidate.banned,
                candidate.ban_reason.clone(),
                candidate.ban_expires,
            )
            .await
            .map_err(admin_user_error)?;
        self.after_database_update(&crate::DatabaseRecord::User(updated.clone()))
            .await?;
        self.delete_user_sessions_with_hooks(user_id).await?;
        self.activity(crate::AuthActivity::UserBanned {
            actor_user_id: actor.user.id,
            user_id,
            reason,
            expires_at,
        })
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
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(crate::AdminError::UserNotFound)?;
        let mut candidate = target.clone();
        candidate.banned = false;
        candidate.ban_reason = None;
        candidate.ban_expires = None;
        let candidate = self.prepare_user_update(&target, candidate).await?;
        let updated = self
            .store
            .update_user_ban(
                user_id,
                candidate.banned,
                candidate.ban_reason,
                candidate.ban_expires,
            )
            .await
            .map_err(admin_user_error)?;
        self.after_database_update(&crate::DatabaseRecord::User(updated.clone()))
            .await?;
        self.activity(crate::AuthActivity::UserUnbanned {
            actor_user_id: actor.user.id,
            user_id,
        })
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
        Ok(self
            .stored_sessions(user_id)
            .await?
            .into_iter()
            .map(|(_, session)| session)
            .collect())
    }

    pub async fn revoke_user_session(
        &self,
        actor: &SessionWithUser,
        session_token: &str,
    ) -> Result<(), AuthError> {
        self.require_admin_permission(actor, "session", &["revoke"])
            .await?;
        let session_id = self
            .find_stored_session(session_token)
            .await?
            .map(|session| session.session.id);
        self.delete_session_token_with_hooks(session_token).await?;
        self.activity(crate::AuthActivity::SessionRevoked {
            actor_user_id: actor.user.id,
            subject_user_id: None,
            session_id,
            self_service: false,
        })
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
        self.delete_user_sessions_with_hooks(user_id).await?;
        self.activity(crate::AuthActivity::UserSessionsRevoked {
            actor_user_id: actor.user.id,
            user_id,
        })
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
        let admin = self.admin_config()?;
        if !admin.allow_impersonating_admins
            && admin.is_admin_target(target.id, &target.role)
            && !admin.authorizes(
                actor.user.id,
                &actor.user.role,
                &crate::admin::permission("user", &["impersonate-admins"]),
            )
        {
            return Err(crate::AdminError::CannotImpersonateAdmin.into());
        }
        let expires_at =
            Utc::now() + chrono::Duration::seconds(admin.impersonation_session_duration_seconds);
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
        self.activity(crate::AuthActivity::ImpersonationStarted {
            actor_user_id: actor.user.id,
            user_id,
            session_id: result.session.session.id,
            expires_at: result.session.session.expires_at,
        })
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
        self.delete_session_id_with_hooks(session.session.id)
            .await?;
        let result = SignInResult {
            token: actor_session_token.to_owned(),
            session: actor_session,
        };
        self.activity(crate::AuthActivity::ImpersonationStopped {
            actor_user_id: actor_id,
            user_id: session.user.id,
            session_id: session.session.id,
        })
        .await;
        Ok(result)
    }

    pub(super) async fn admin_session_user(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        let Some(admin) = self
            .plugins
            .find::<crate::AdminPlugin>()
            .map(crate::AdminPlugin::config)
        else {
            return Ok(user);
        };
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
            admin.banned_user_message.clone(),
        ))
    }
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
