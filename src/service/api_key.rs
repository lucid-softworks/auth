use super::AuthService;
use crate::{ApiKey, AuthError, IssuedApiKey, NewApiKey, SessionWithUser, VerifiedApiKey};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngExt;
use rand_core::OsRng;
use serde_json::json;
use uuid::Uuid;

impl AuthService {
    pub async fn issue_api_key(
        &self,
        actor: &SessionWithUser,
        mut input: NewApiKey,
    ) -> Result<IssuedApiKey, AuthError> {
        require_account(actor)?;
        if self.step_up_required(&actor.principal()) {
            return Err(AuthError::StepUpRequired);
        }
        validate_input(&input)?;
        normalize_permissions(&mut input);

        let id = Uuid::new_v4();
        let secret_bytes: [u8; 48] = rand::rng().random();
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
        let key = format!("{}{}.{}", input.prefix, id.simple(), secret);
        let now = Utc::now();
        let api_key = self
            .store
            .create_api_key(ApiKey {
                id,
                config_id: input.config_id,
                name: input.name.trim().to_owned(),
                start: format!("{}{}", input.prefix, &id.simple().to_string()[..8]),
                prefix: input.prefix,
                key_hash: hash_api_key(key.clone()).await?,
                reference_id: actor.user.id,
                enabled: true,
                rate_limit_enabled: true,
                rate_limit_window_seconds: input.rate_limit_window_seconds,
                rate_limit_max: input.rate_limit_max,
                request_count: 0,
                last_request: None,
                expires_at: input.expires_at,
                permissions: input.permissions,
                created_at: now,
                updated_at: now,
            })
            .await?;
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "api_key.created",
            Some(api_key.id.to_string()),
            json!({
                "configId": api_key.config_id,
                "name": api_key.name,
                "permissions": api_key.permissions,
                "expiresAt": api_key.expires_at,
            }),
        )
        .await?;
        Ok(IssuedApiKey { api_key, key })
    }

    pub async fn list_api_keys(
        &self,
        actor: &SessionWithUser,
        config_id: &str,
    ) -> Result<Vec<ApiKey>, AuthError> {
        require_account(actor)?;
        validate_identifier(config_id, "API key configuration ID")?;
        self.store.list_api_keys(actor.user.id, config_id).await
    }

    pub async fn revoke_api_key(
        &self,
        actor: &SessionWithUser,
        api_key_id: Uuid,
    ) -> Result<(), AuthError> {
        require_account(actor)?;
        if self.step_up_required(&actor.principal()) {
            return Err(AuthError::StepUpRequired);
        }
        if !self
            .store
            .revoke_api_key(actor.user.id, api_key_id, Utc::now())
            .await?
        {
            return Err(AuthError::NotFound);
        }
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "api_key.revoked",
            Some(api_key_id.to_string()),
            json!({}),
        )
        .await
    }

    pub async fn verify_api_key(
        &self,
        key: &str,
        config_id: &str,
    ) -> Result<VerifiedApiKey, AuthError> {
        if key.len() > 256 {
            return Err(AuthError::InvalidApiKey);
        }
        let id = api_key_id(key).ok_or(AuthError::InvalidApiKey)?;
        let stored = self
            .store
            .find_api_key(id)
            .await?
            .filter(|api_key| {
                api_key.enabled && api_key.config_id == config_id && api_key.expires_at > Utc::now()
            })
            .ok_or(AuthError::InvalidApiKey)?;
        if !verify_api_key_hash(key.to_owned(), stored.key_hash.clone()).await? {
            return Err(AuthError::InvalidApiKey);
        }
        let user = self
            .store
            .find_user_by_id(stored.reference_id)
            .await?
            .filter(active_account)
            .ok_or(AuthError::InvalidApiKey)?;
        let api_key = self
            .store
            .record_api_key_use(id, Utc::now())
            .await?
            .ok_or(AuthError::RateLimited)?;
        Ok(VerifiedApiKey { api_key, user })
    }
}

fn require_account(actor: &SessionWithUser) -> Result<(), AuthError> {
    if actor.user.is_anonymous
        || actor.session.actor_user_id.is_some()
        || actor.user.must_change_password
    {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

fn active_account(user: &crate::AuthUser) -> bool {
    !user.is_anonymous
        && (!user.banned
            || user
                .ban_expires
                .is_some_and(|expires| expires <= Utc::now()))
}

fn validate_input(input: &NewApiKey) -> Result<(), AuthError> {
    validate_identifier(&input.config_id, "API key configuration ID")?;
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return invalid("API key name must contain 1 to 100 characters");
    }
    if !(3..=32).contains(&input.prefix.len())
        || !input.prefix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return invalid("API key prefix must contain 3 to 32 lowercase letters, numbers, _ or -");
    }
    let now = Utc::now();
    if input.expires_at <= now + Duration::minutes(5)
        || input.expires_at > now + Duration::days(365)
    {
        return invalid("API key expiry must be between five minutes and one year");
    }
    if !(1..=86_400).contains(&input.rate_limit_window_seconds)
        || !(1..=100_000).contains(&input.rate_limit_max)
    {
        return invalid("API key rate limits are outside the supported range");
    }
    if input.permissions.is_empty()
        || input.permissions.len() > 32
        || !input.permissions.iter().all(|(resource, actions)| {
            valid_permission_token(resource)
                && !actions.is_empty()
                && actions.len() <= 32
                && actions.iter().all(|action| valid_permission_token(action))
        })
    {
        return invalid("API key permissions are invalid");
    }
    Ok(())
}

fn normalize_permissions(input: &mut NewApiKey) {
    for actions in input.permissions.values_mut() {
        actions.sort_unstable();
        actions.dedup();
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<(), AuthError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return invalid(&format!(
            "{label} must contain lowercase letters, numbers, _ or -"
        ));
    }
    Ok(())
}

fn valid_permission_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn api_key_id(key: &str) -> Option<Uuid> {
    let (prefix_and_id, secret) = key.rsplit_once('.')?;
    let id = prefix_and_id.get(prefix_and_id.len().checked_sub(32)?..)?;
    (!secret.is_empty())
        .then(|| Uuid::parse_str(id).ok())
        .flatten()
}

async fn hash_api_key(key: String) -> Result<String, AuthError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(key.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| AuthError::Storage(error.to_string()))
    })
    .await
    .map_err(|_| AuthError::Worker)?
}

async fn verify_api_key_hash(key: String, key_hash: String) -> Result<bool, AuthError> {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&key_hash).ok().is_some_and(|hash| {
            Argon2::default()
                .verify_password(key.as_bytes(), &hash)
                .is_ok()
        })
    })
    .await
    .map_err(|_| AuthError::Worker)
}

fn invalid<T>(message: &str) -> Result<T, AuthError> {
    Err(AuthError::InvalidRequest(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore, NewPasswordUser};
    use std::{collections::BTreeMap, sync::Arc};

    async fn owner() -> (AuthService, crate::SignInResult) {
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([17_u8; 32]).unwrap(),
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
            .unwrap();
        (service, owner)
    }

    fn input() -> NewApiKey {
        NewApiKey {
            config_id: "example-service".into(),
            name: "Codex".into(),
            prefix: "example_key_".into(),
            expires_at: Utc::now() + Duration::days(30),
            permissions: BTreeMap::from([
                ("home".into(), vec!["read".into()]),
                ("lights".into(), vec!["control".into()]),
            ]),
            rate_limit_window_seconds: 60,
            rate_limit_max: 120,
        }
    }

    #[tokio::test]
    async fn issued_keys_are_one_way_verified_and_revocable() {
        let (service, owner) = owner().await;
        let issued = service
            .issue_api_key(&owner.session, input())
            .await
            .unwrap();

        assert!(issued.key.starts_with("example_key_"));
        assert!(!issued.api_key.key_hash.contains(&issued.key));
        assert_eq!(api_key_id(&issued.key), Some(issued.api_key.id));
        assert!(
            verify_api_key_hash(issued.key.clone(), issued.api_key.key_hash.clone())
                .await
                .unwrap()
        );
        let verified = service
            .verify_api_key(&issued.key, "example-service")
            .await
            .unwrap();
        assert!(verified.api_key.permits("home", "read"));
        assert_eq!(verified.api_key.request_count, 1);

        service
            .revoke_api_key(&owner.session, issued.api_key.id)
            .await
            .unwrap();
        assert!(matches!(
            service.verify_api_key(&issued.key, "example-service").await,
            Err(AuthError::InvalidApiKey)
        ));
    }

    #[tokio::test]
    async fn keys_are_bound_to_their_configuration_and_rate_limit() {
        let (service, owner) = owner().await;
        let mut input = input();
        input.rate_limit_max = 1;
        let issued = service.issue_api_key(&owner.session, input).await.unwrap();

        assert!(matches!(
            service.verify_api_key(&issued.key, "other").await,
            Err(AuthError::InvalidApiKey)
        ));
        service
            .verify_api_key(&issued.key, "example-service")
            .await
            .unwrap();
        assert!(matches!(
            service.verify_api_key(&issued.key, "example-service").await,
            Err(AuthError::RateLimited)
        ));
    }
}
