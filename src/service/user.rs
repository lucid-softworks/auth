use super::{AuthService, password::normalize_username};
use crate::{
    AdminCreateUser, AuthError, AuthUser, NewPasswordUser, PasswordCredentialChanged,
    PasswordCredentialSource, SessionWithUser, UsernameError,
};
use chrono::Utc;
use uuid::Uuid;

impl AuthService {
    pub async fn create_user(
        &self,
        actor: &SessionWithUser,
        input: NewPasswordUser,
    ) -> Result<AuthUser, AuthError> {
        let mut data = serde_json::Map::new();
        data.insert("username".into(), input.username.into());
        self.create_admin_user(
            actor,
            AdminCreateUser {
                email: input.email.unwrap_or_default(),
                password: Some(input.password),
                name: input.name,
                roles: vec![input.role],
                data,
            },
        )
        .await
    }

    pub async fn create_admin_user(
        &self,
        actor: &SessionWithUser,
        mut input: AdminCreateUser,
    ) -> Result<AuthUser, AuthError> {
        self.require_admin_permission(actor, "user", &["create"])
            .await?;
        let admin = self.admin_config()?;
        let role = if input.roles.is_empty() {
            admin.default_role.clone()
        } else {
            self.require_admin_permission(actor, "user", &["set-role"])
                .await?;
            input.roles.join(",")
        };
        validate_admin_roles(admin, &role)?;
        self.plugins
            .authorize_user_management(
                self.store.as_ref(),
                &crate::UserManagementOperation {
                    actor,
                    action: crate::UserManagementAction::Create { role: &role },
                },
            )
            .await?;
        if let Some(password) = &input.password {
            self.validate_new_password(password).await?;
        }
        let user = admin_user_from_input(&mut input, role)?;
        if self.store.find_user_by_email(&user.email).await?.is_some() {
            return Err(crate::AdminError::UserAlreadyExistsEmail.into());
        }
        if user.banned {
            self.require_admin_permission(actor, "user", &["ban"])
                .await?;
        }
        let has_password = input.password.is_some();
        let user = self
            .persist_admin_user(user, input.password)
            .await
            .map_err(|error| match error {
                AuthError::Username(UsernameError::AlreadyTaken) => AuthError::UserAlreadyExists,
                error => super::access::admin_user_error(error),
            })?;
        if has_password {
            self.plugins
                .password_credential_changed(&PasswordCredentialChanged {
                    user_id: user.id,
                    source: PasswordCredentialSource::AdministratorCreated,
                })
                .await?;
        }
        self.activity(crate::AuthActivity::UserCreated {
            actor_user_id: actor.user.id,
            user_id: user.id,
            role: user.role.clone(),
            username: user.username.clone(),
        })
        .await;
        Ok(user)
    }

    async fn persist_admin_user(
        &self,
        user: AuthUser,
        password: Option<String>,
    ) -> Result<AuthUser, AuthError> {
        let user = self.prepare_user_create(user).await?;
        let user = self.store.create_user_without_account(user).await?;
        self.finish_user_create(&user).await?;
        let Some(password) = password else {
            return Ok(user);
        };
        let password_hash = self.hash_password(password).await?;
        let credential = self
            .prepare_credential_account(user.id, password_hash, user.created_at, false)
            .await?;
        let credential = self.store.link_oauth_account(credential).await?;
        self.finish_account_create(&credential).await?;
        Ok(user)
    }

    pub async fn set_user_password(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        password: String,
    ) -> Result<(), AuthError> {
        self.require_admin_permission(actor, "user", &["set-password"])
            .await?;
        self.validate_new_password(&password).await?;
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(crate::AdminError::UserNotFound)?;
        if target.is_anonymous {
            return Err(AuthError::Forbidden);
        }
        self.store
            .set_password_hash(user_id, self.hash_password(password).await?)
            .await?;
        self.plugins
            .password_credential_changed(&PasswordCredentialChanged {
                user_id,
                source: PasswordCredentialSource::AdministratorReset,
            })
            .await?;
        self.activity(crate::AuthActivity::AdministratorResetPassword {
            actor_user_id: actor.user.id,
            user_id,
        })
        .await;
        Ok(())
    }

    pub async fn remove_user(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        self.require_admin_permission(actor, "user", &["delete"])
            .await?;
        if actor.user.id == user_id {
            return Err(crate::AdminError::CannotRemoveSelf.into());
        }
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(crate::AdminError::UserNotFound)?;
        if target.is_anonymous {
            return Err(AuthError::Forbidden);
        }
        self.plugins
            .authorize_user_management(
                self.store.as_ref(),
                &crate::UserManagementOperation {
                    actor,
                    action: crate::UserManagementAction::Delete { target: &target },
                },
            )
            .await?;
        self.delete_user_with_hooks(target.clone()).await?;
        self.activity(crate::AuthActivity::UserRemoved {
            actor_user_id: actor.user.id,
            user_id,
            name: target.name,
            role: target.role,
            username: target.username,
        })
        .await;
        Ok(())
    }
}

fn admin_user_from_input(input: &mut AdminCreateUser, role: String) -> Result<AuthUser, AuthError> {
    let raw_username = input
        .data
        .remove("username")
        .and_then(|value| value.as_str().map(str::to_owned));
    let username = raw_username
        .as_deref()
        .map(normalize_username)
        .transpose()
        .map_err(|_| invalid_username_request())?;
    let name = input.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(AuthError::InvalidRequest(
            "name must contain 1-100 characters".into(),
        ));
    }
    let email = admin_email(&input.email, username.as_deref())?;
    let now = Utc::now();
    crate::admin::sanitize_additional_fields(&mut input.data);
    Ok(AuthUser {
        id: Uuid::new_v4(),
        username,
        display_username: raw_username,
        name: name.to_owned(),
        email,
        email_verified: take_bool(&mut input.data, "emailVerified"),
        image: take_string(&mut input.data, "image"),
        role,
        is_anonymous: false,
        banned: take_bool(&mut input.data, "banned"),
        ban_reason: take_string(&mut input.data, "banReason"),
        ban_expires: input
            .data
            .remove("banExpires")
            .and_then(|value| serde_json::from_value(value).ok()),
        additional_fields: std::mem::take(&mut input.data),
        created_at: now,
        updated_at: now,
    })
}

fn admin_email(input: &str, username: Option<&str>) -> Result<String, AuthError> {
    let email = if input.trim().is_empty() {
        username
            .map(|username| format!("{username}@users.localhost"))
            .ok_or(AuthError::InvalidEmail)?
    } else {
        input.trim().to_lowercase()
    };
    valid_email(&email)
        .then_some(email)
        .ok_or(AuthError::InvalidEmail)
}

fn take_bool(data: &mut serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    data.remove(key)
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

fn take_string(data: &mut serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    data.remove(key)
        .and_then(|value| value.as_str().map(str::to_owned))
}

fn invalid_username_request() -> AuthError {
    AuthError::InvalidRequest(
        "username must contain 3-30 ASCII letters, numbers, dots or underscores".into(),
    )
}

pub(super) fn validate_admin_roles(
    config: &crate::AdminConfig,
    roles: &str,
) -> Result<(), AuthError> {
    let roles: Vec<_> = roles.split(',').map(str::trim).collect();
    if roles.is_empty()
        || roles.iter().any(|role| role.is_empty())
        || (config.has_custom_roles() && roles.iter().any(|role| !config.roles.contains_key(*role)))
    {
        return Err(crate::AdminError::RoleNotFound.into());
    }
    Ok(())
}

pub(super) fn valid_email(email: &str) -> bool {
    email.len() <= 254
        && !email.contains(char::is_whitespace)
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore};
    use std::sync::Arc;

    async fn owner() -> (AuthService, SessionWithUser) {
        let mut config = AuthConfig::new([41_u8; 32]).unwrap();
        config
            .add_plugin(crate::AdminPlugin::new(
                crate::OwnerPolicyPlugin::admin_config(),
            ))
            .unwrap();
        config.add_plugin(crate::OwnerPolicyPlugin).unwrap();
        let service = AuthService::new(Arc::new(MemoryStore::default()), config);
        service
            .provision_password_user(NewPasswordUser {
                username: "owner".into(),
                name: "Owner".into(),
                email: None,
                password: "password".into(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        let owner = service
            .sign_in_username("owner", "password".into(), None, None)
            .await
            .unwrap()
            .session;
        (service, owner)
    }

    #[tokio::test]
    async fn owner_creates_resets_and_removes_a_user() {
        let (service, owner) = owner().await;
        let user = service
            .create_user(
                &owner,
                NewPasswordUser {
                    username: "Casey".into(),
                    name: "Casey".into(),
                    email: Some("CASEY@example.com".into()),
                    password: "initial-password".into(),
                    role: "member".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(user.username.as_deref(), Some("casey"));
        assert_eq!(user.email, "casey@example.com");
        assert!(
            service
                .sign_in_username("casey", "initial-password".into(), None, None)
                .await
                .is_ok()
        );

        service
            .set_user_password(&owner, user.id, "replacement-password".into())
            .await
            .unwrap();
        assert!(
            service
                .sign_in_username("casey", "initial-password".into(), None, None)
                .await
                .is_err()
        );
        assert!(
            service
                .sign_in_username("casey", "replacement-password".into(), None, None)
                .await
                .is_ok()
        );

        service.remove_user(&owner, user.id).await.unwrap();
        assert!(
            service
                .store
                .find_user_by_id(user.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_accounts_and_self_removal() {
        let (service, owner) = owner().await;
        let duplicate = service
            .create_user(
                &owner,
                NewPasswordUser {
                    username: "owner".into(),
                    name: "Another owner".into(),
                    email: Some("other@example.com".into()),
                    password: "another-password".into(),
                    role: "viewer".into(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(duplicate, AuthError::UserAlreadyExists));
        let removal = service
            .remove_user(&owner, owner.user.id)
            .await
            .unwrap_err();
        assert!(matches!(
            removal,
            AuthError::Admin(crate::AdminError::CannotRemoveSelf)
        ));
    }
}
