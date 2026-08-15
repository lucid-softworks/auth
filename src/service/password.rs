use super::{AuthService, HashedPasswordUser, SignInResult};
use crate::{Assurance, AuthError, AuthUser, NewPasswordUser};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chrono::Utc;
use rand_core::OsRng;
use uuid::Uuid;

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
        let password = input.password;
        let password_hash = tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|error| AuthError::Storage(error.to_string()))
        })
        .await
        .map_err(|_| AuthError::Worker)??;
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
}

fn normalize_username(value: &str) -> Result<String, AuthError> {
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
}
