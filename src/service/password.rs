use super::{AuthService, HashedPasswordUser, SignInResult};
use crate::{Assurance, AuthError, AuthUser, NewPasswordUser, SessionWithUser};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chrono::Utc;
use rand_core::OsRng;
use serde_json::json;
use uuid::Uuid;

/// A password change and an optional replacement for the current session.
#[derive(Debug, Clone)]
pub struct PasswordChangeResult {
    pub user: AuthUser,
    pub replacement_session: Option<SignInResult>,
}

impl AuthService {
    pub async fn provision_password_user(
        &self,
        input: NewPasswordUser,
    ) -> Result<AuthUser, AuthError> {
        normalize_username(&input.username)?;
        if input.password.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "password must not be empty".into(),
            ));
        }
        let password_hash = hash_password(input.password).await?;
        self.provision_password_hash_user(HashedPasswordUser {
            username: input.username,
            name: input.name,
            email: input.email,
            password_hash,
            role: input.role,
        })
        .await
    }

    pub async fn provision_password_hash_user(
        &self,
        input: HashedPasswordUser,
    ) -> Result<AuthUser, AuthError> {
        PasswordHash::new(&input.password_hash).map_err(|error| {
            AuthError::InvalidConfiguration(format!("invalid password hash: {error}"))
        })?;
        let username = normalize_username(&input.username)?;
        let now = Utc::now();
        let email = input
            .email
            .unwrap_or_else(|| format!("{username}@users.localhost"));
        self.store
            .upsert_password_user(
                AuthUser {
                    id: Uuid::new_v4(),
                    username: Some(username.clone()),
                    display_username: Some(input.username),
                    name: input.name,
                    email,
                    email_verified: false,
                    image: None,
                    role: input.role,
                    is_anonymous: false,
                    banned: false,
                    ban_reason: None,
                    ban_expires: None,
                    created_at: now,
                    updated_at: now,
                },
                input.password_hash,
            )
            .await
    }

    pub async fn sign_in_username(
        &self,
        username: &str,
        password: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let username = normalize_username(username).map_err(|_| AuthError::InvalidCredentials)?;
        self.enforce_rate_limit(&username).await?;
        let user = self.store.find_user_by_username(&username).await?;
        let password_hash = match &user {
            Some(user) => self.store.find_password_hash(user.id).await?,
            None => None,
        };
        let password_valid = verify_password(password, password_hash).await?;
        let Some(user) = user.filter(|_| password_valid) else {
            self.record_failure(&username).await;
            return Err(AuthError::InvalidCredentials);
        };
        if user.banned && user.ban_expires.is_none_or(|expires| expires > Utc::now()) {
            return Err(AuthError::AccountDisabled);
        }
        self.failures.lock().await.remove(&username);
        let assurance = if self.store.list_passkeys(user.id).await?.is_empty() {
            Assurance::Password
        } else {
            Assurance::PasswordPendingPasskey
        };
        self.create_session(user, assurance, None, None, ip_address, user_agent)
            .await
    }

    pub async fn username_available(&self, username: &str) -> Result<bool, AuthError> {
        let username = normalize_username(username)?;
        Ok(self.store.find_user_by_username(&username).await?.is_none())
    }

    pub async fn change_password(
        &self,
        session: &SessionWithUser,
        current_password: String,
        new_password: String,
        revoke_other_sessions: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<PasswordChangeResult, AuthError> {
        if session.user.is_anonymous || session.session.actor_user_id.is_some() {
            return Err(AuthError::Forbidden);
        }
        validate_password(&new_password)?;
        let current_hash = self
            .store
            .find_password_hash(session.user.id)
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;
        if !verify_password(current_password, Some(current_hash)).await? {
            return Err(AuthError::InvalidPassword);
        }
        let password_hash = hash_password(new_password).await?;
        self.store
            .update_password_hash(session.user.id, password_hash)
            .await?;

        let replacement_session = if revoke_other_sessions {
            self.store.delete_user_sessions(session.user.id).await?;
            Some(
                self.create_session(
                    session.user.clone(),
                    session.session.assurance,
                    None,
                    None,
                    ip_address,
                    user_agent,
                )
                .await?,
            )
        } else {
            None
        };
        self.audit(
            session.user.id,
            Some(session.user.id),
            "password.changed",
            None,
            json!({ "revokedOtherSessions": revoke_other_sessions }),
        )
        .await?;
        Ok(PasswordChangeResult {
            user: session.user.clone(),
            replacement_session,
        })
    }
}

pub(super) fn normalize_username(value: &str) -> Result<String, AuthError> {
    let value = value.trim().to_lowercase();
    if !(3..=30).contains(&value.len())
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
    {
        return Err(AuthError::InvalidConfiguration(
            "username must contain 3-30 ASCII letters, numbers, dots or underscores".into(),
        ));
    }
    Ok(value)
}

async fn verify_password(
    password: String,
    password_hash: Option<String>,
) -> Result<bool, AuthError> {
    tokio::task::spawn_blocking(move || {
        let Some(password_hash) = password_hash else {
            let salt = SaltString::generate(&mut OsRng);
            let _ = Argon2::default().hash_password(password.as_bytes(), &salt);
            return false;
        };
        PasswordHash::new(&password_hash).ok().is_some_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
    })
    .await
    .map_err(|_| AuthError::Worker)
}

pub(super) fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.len() < 8 {
        return Err(AuthError::PasswordTooShort);
    }
    if password.len() > 128 {
        return Err(AuthError::PasswordTooLong);
    }
    Ok(())
}

pub(super) async fn hash_password(password: String) -> Result<String, AuthError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| AuthError::Storage(error.to_string()))
    })
    .await
    .map_err(|_| AuthError::Worker)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore};
    use std::sync::Arc;

    #[tokio::test]
    async fn reprovisioning_preserves_an_account_owned_password() {
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([31_u8; 32]).unwrap(),
        );
        for password in ["original-password", "configured-replacement"] {
            service
                .provision_password_user(NewPasswordUser {
                    username: "luna".into(),
                    name: "Luna".into(),
                    email: None,
                    password: password.into(),
                    role: "owner".into(),
                })
                .await
                .unwrap();
        }

        assert!(
            service
                .sign_in_username("luna", "original-password".into(), None, None)
                .await
                .is_ok()
        );
        assert!(
            service
                .sign_in_username("luna", "configured-replacement".into(), None, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn changes_a_password_and_rotates_other_sessions() {
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([41_u8; 32]).unwrap(),
        );
        service
            .provision_password_user(NewPasswordUser {
                username: "luna".into(),
                name: "Luna".into(),
                email: None,
                password: "old-password".into(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        let current = service
            .sign_in_username("luna", "old-password".into(), None, None)
            .await
            .unwrap();
        let other = service
            .sign_in_username("luna", "old-password".into(), None, None)
            .await
            .unwrap();

        let changed = service
            .change_password(
                &current.session,
                "old-password".into(),
                "new-password".into(),
                true,
                None,
                None,
            )
            .await
            .unwrap();

        assert!(service.session(&current.token).await.unwrap().is_none());
        assert!(service.session(&other.token).await.unwrap().is_none());
        assert!(
            service
                .session(&changed.replacement_session.unwrap().token)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            service
                .sign_in_username("luna", "old-password".into(), None, None)
                .await
                .is_err()
        );
        assert!(
            service
                .sign_in_username("luna", "new-password".into(), None, None)
                .await
                .is_ok()
        );
    }
}
