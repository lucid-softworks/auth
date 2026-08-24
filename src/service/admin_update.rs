use super::{AuthService, access::admin_user_error, user::validate_admin_roles};
use crate::{AdminUserUpdate, AuthError, AuthUser, SessionWithUser};
use uuid::Uuid;

impl AuthService {
    pub async fn admin_update_user(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        mut update: AdminUserUpdate,
    ) -> Result<AuthUser, AuthError> {
        self.require_admin_permission(actor, "user", &["update"])
            .await?;
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(crate::AdminError::UserNotFound)?;
        let revoke_target_sessions = self.authorize_admin_update(actor, &target, &update).await?;
        validate_updated_email(self, user_id, update.email.as_deref()).await?;
        update.additional_fields =
            self.update_additional_fields(crate::DatabaseModel::User, update.additional_fields)?;
        let banned = update.banned == Some(true);
        let candidate = self
            .prepare_user_update(&target, admin_update_candidate(&target, &update))
            .await?;
        update = admin_update_from_candidate(candidate);
        let user = self
            .store
            .admin_update_user(user_id, update)
            .await
            .map_err(admin_user_error)?;
        self.after_database_update(&crate::DatabaseRecord::User(user.clone()))
            .await?;
        if banned || revoke_target_sessions {
            self.delete_user_sessions_with_hooks(user_id).await?;
        }
        Ok(user)
    }

    async fn authorize_admin_update(
        &self,
        actor: &SessionWithUser,
        target: &AuthUser,
        update: &AdminUserUpdate,
    ) -> Result<bool, AuthError> {
        let mut revoke_target_sessions = false;
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
        if update.banned == Some(true) && actor.user.id == target.id {
            return Err(crate::AdminError::CannotBanSelf.into());
        }
        if let Some(role) = &update.role {
            validate_admin_roles(self.admin_config()?, role)?;
            let decision = self
                .plugins
                .authorize_user_management(
                    self.store.as_ref(),
                    &crate::UserManagementOperation {
                        actor,
                        action: crate::UserManagementAction::ChangeRole {
                            target,
                            new_role: role,
                        },
                    },
                )
                .await?;
            revoke_target_sessions |= decision.revoke_target_sessions;
        }
        if let Some(banned) = update.banned {
            let decision = self
                .plugins
                .authorize_user_management(
                    self.store.as_ref(),
                    &crate::UserManagementOperation {
                        actor,
                        action: crate::UserManagementAction::ChangeBan { target, banned },
                    },
                )
                .await?;
            revoke_target_sessions |= decision.revoke_target_sessions;
        }
        Ok(revoke_target_sessions)
    }
}

fn admin_update_candidate(target: &AuthUser, update: &AdminUserUpdate) -> AuthUser {
    let mut user = target.clone();
    if let Some(value) = &update.name {
        user.name.clone_from(value);
    }
    if let Some(value) = &update.email {
        user.email.clone_from(value);
    }
    if let Some(value) = update.email_verified {
        user.email_verified = value;
    }
    if let Some(value) = &update.image {
        user.image.clone_from(value);
    }
    if let Some(value) = &update.role {
        user.role.clone_from(value);
    }
    if let Some(value) = update.banned {
        user.banned = value;
    }
    if let Some(value) = &update.ban_reason {
        user.ban_reason.clone_from(value);
    }
    if let Some(value) = &update.ban_expires {
        user.ban_expires.clone_from(value);
    }
    user.additional_fields
        .extend(update.additional_fields.clone());
    user
}

fn admin_update_from_candidate(user: AuthUser) -> AdminUserUpdate {
    AdminUserUpdate {
        name: Some(user.name),
        email: Some(user.email),
        email_verified: Some(user.email_verified),
        image: Some(user.image),
        role: Some(user.role),
        banned: Some(user.banned),
        ban_reason: Some(user.ban_reason),
        ban_expires: Some(user.ban_expires),
        additional_fields: user.additional_fields,
    }
}

async fn validate_updated_email(
    service: &AuthService,
    user_id: Uuid,
    email: Option<&str>,
) -> Result<(), AuthError> {
    let Some(email) = email else {
        return Ok(());
    };
    if !super::user::valid_email(email) {
        return Err(AuthError::InvalidEmail);
    }
    if service
        .store
        .find_user_by_email(email)
        .await?
        .is_some_and(|user| user.id != user_id)
    {
        return Err(crate::AdminError::UserAlreadyExistsEmail.into());
    }
    Ok(())
}
