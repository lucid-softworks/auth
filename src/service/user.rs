use super::{
    AuthService,
    password::{hash_password, normalize_username},
};
use crate::{AuthError, AuthUser, NewPasswordUser, SessionWithUser, UsernameError};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

const MANAGED_ROLES: [&str; 3] = ["owner", "member", "viewer"];

impl AuthService {
    pub async fn create_user(
        &self,
        actor: &SessionWithUser,
        input: NewPasswordUser,
    ) -> Result<AuthUser, AuthError> {
        self.require_recent_owner(actor)?;
        validate_managed_role(&input.role)?;
        self.validate_new_password(&input.password).await?;
        let username = normalize_username(&input.username).map_err(|_| {
            AuthError::InvalidRequest(
                "username must contain 3-30 ASCII letters, numbers, dots or underscores".into(),
            )
        })?;
        let name = input.name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err(AuthError::InvalidRequest(
                "name must contain 1-100 characters".into(),
            ));
        }
        let email = input
            .email
            .unwrap_or_else(|| format!("{username}@users.localhost"))
            .trim()
            .to_lowercase();
        if !valid_email(&email) {
            return Err(AuthError::InvalidRequest("email is invalid".into()));
        }
        let now = Utc::now();
        let user = self
            .store
            .create_password_user(
                AuthUser {
                    id: Uuid::new_v4(),
                    username: Some(username),
                    display_username: Some(input.username.trim().to_owned()),
                    name: name.to_owned(),
                    email,
                    email_verified: false,
                    image: None,
                    role: input.role,
                    is_anonymous: false,
                    must_change_password: true,
                    banned: false,
                    ban_reason: None,
                    ban_expires: None,
                    created_at: now,
                    updated_at: now,
                },
                hash_password(input.password).await?,
            )
            .await
            .map_err(|error| match error {
                AuthError::Username(UsernameError::AlreadyTaken) => AuthError::UserAlreadyExists,
                error => error,
            })?;
        self.audit(
            actor.user.id,
            Some(user.id),
            "user.created",
            Some(user.id.to_string()),
            json!({ "role": user.role, "username": user.username }),
        )
        .await;
        Ok(user)
    }

    pub async fn set_user_password(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
        password: String,
    ) -> Result<(), AuthError> {
        self.require_recent_owner(actor)?;
        self.validate_new_password(&password).await?;
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if target.is_anonymous {
            return Err(AuthError::Forbidden);
        }
        self.store
            .set_password_hash(user_id, hash_password(password).await?)
            .await?;
        self.store.delete_user_sessions(user_id).await?;
        self.store.delete_user_passkeys(user_id).await?;
        self.store.delete_recovery_codes(user_id).await?;
        self.audit(
            actor.user.id,
            Some(user_id),
            "password.reset_by_owner",
            Some(user_id.to_string()),
            json!({ "revokedSessions": true, "resetMfa": true }),
        )
        .await;
        Ok(())
    }

    pub async fn remove_user(
        &self,
        actor: &SessionWithUser,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        self.require_recent_owner(actor)?;
        if actor.user.id == user_id {
            return Err(AuthError::Forbidden);
        }
        let target = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if target.is_anonymous {
            return Err(AuthError::Forbidden);
        }
        self.protect_final_owner(&target, true).await?;
        self.delete_user_with_hooks(target.clone()).await?;
        self.audit(
            actor.user.id,
            None,
            "user.removed",
            Some(user_id.to_string()),
            json!({ "name": target.name, "role": target.role, "username": target.username }),
        )
        .await;
        Ok(())
    }
}

pub(super) fn validate_managed_role(role: &str) -> Result<(), AuthError> {
    if MANAGED_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(AuthError::InvalidRequest(
            "role must be owner, member, or viewer".into(),
        ))
    }
}

fn valid_email(email: &str) -> bool {
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
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([41_u8; 32]).unwrap(),
        );
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
        assert!(matches!(removal, AuthError::Forbidden));
    }
}
