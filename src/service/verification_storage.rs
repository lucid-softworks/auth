use super::AuthService;
use crate::{
    AuthError, DatabaseModel, DatabaseRecord, VerificationIdentifierStorage, VerificationValue,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

impl AuthService {
    /// Creates a Better Auth verification value using configured identifier,
    /// hook, database, secondary-storage, and TTL behavior.
    pub async fn create_verification_value(
        &self,
        value: VerificationValue,
    ) -> Result<(), AuthError> {
        self.create_verification_record(value).await
    }

    pub(super) async fn create_verification_record(
        &self,
        mut value: VerificationValue,
    ) -> Result<(), AuthError> {
        value.additional_fields =
            self.create_additional_fields(DatabaseModel::Verification, value.additional_fields)?;
        value.identifier = self
            .processed_verification_identifier(&value.purpose, &value.identifier)
            .await?;
        let value = match self
            .before_database_create(DatabaseRecord::Verification(value))
            .await?
        {
            DatabaseRecord::Verification(value) => value,
            _ => unreachable!("database hook model was validated"),
        };
        if self.verification_uses_database() {
            self.store.create_verification(value.clone()).await?;
        }
        self.cache_verification(&value).await?;
        self.after_database_create(&DatabaseRecord::Verification(value))
            .await
    }

    /// Finds a Better Auth verification value through the configured
    /// database/secondary-storage route.
    pub async fn find_verification_value(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        self.find_verification_record(purpose, identifier, true)
            .await
    }

    pub(super) async fn find_verification_record(
        &self,
        purpose: &str,
        identifier: &str,
        cleanup: bool,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let candidates = self
            .verification_identifier_candidates(purpose, identifier)
            .await?;
        if let Some(secondary) = &self.config.secondary_storage {
            for candidate in &candidates {
                if let Some(raw) = secondary.get(&verification_key(candidate)).await?
                    && let Ok(value) = serde_json::from_str(&raw)
                {
                    return Ok(Some(value));
                }
            }
            if !self.config.verification.store_in_database {
                return Ok(None);
            }
        }
        let mut found = None;
        for candidate in candidates {
            if let Some(value) = self.store.find_verification(purpose, &candidate).await? {
                found = Some(value);
                break;
            }
        }
        if cleanup && !self.config.verification.disable_cleanup {
            self.store.delete_expired_verifications(Utc::now()).await?;
        }
        Ok(found)
    }

    pub(super) async fn consume_verification_record(
        &self,
        purpose: &str,
        identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let candidates = self
            .verification_identifier_candidates(purpose, identifier)
            .await?;
        if let Some(secondary) = &self.config.secondary_storage
            && !self.config.verification.store_in_database
        {
            for candidate in &candidates {
                let Some(raw) = secondary
                    .get_and_delete(&verification_key(candidate))
                    .await?
                else {
                    continue;
                };
                for stale in candidates.iter().filter(|value| *value != candidate) {
                    secondary.delete(&verification_key(stale)).await?;
                }
                let value: VerificationValue =
                    serde_json::from_str(&raw).map_err(|error| verification_json("read", error))?;
                return Ok((value.expires_at > now).then_some(value));
            }
            return Ok(None);
        }
        let current = self.find_verification_value(purpose, identifier).await?;
        if let Some(candidate) = &current {
            self.before_database_delete(&DatabaseRecord::Verification(candidate.clone()))
                .await?;
        }
        let mut consumed = None;
        for candidate in &candidates {
            if let Some(value) = self
                .store
                .consume_verification(purpose, candidate, now)
                .await?
            {
                consumed = Some(value);
                break;
            }
        }
        if let Some(secondary) = &self.config.secondary_storage
            && consumed.is_some()
        {
            for candidate in &candidates {
                secondary.delete(&verification_key(candidate)).await?;
            }
        }
        if let Some(value) = &consumed {
            self.after_database_delete(&DatabaseRecord::Verification(value.clone()))
                .await?;
        }
        Ok(consumed)
    }

    /// Atomically consumes one unexpired Better Auth verification value.
    pub async fn consume_verification_value(
        &self,
        purpose: &str,
        identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        self.consume_verification_record(purpose, identifier, now)
            .await
    }

    /// Deletes one verification identifier from every configured backing store.
    pub async fn delete_verification_value(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let candidates = self
            .verification_identifier_candidates(purpose, identifier)
            .await?;
        let current = self.find_verification_value(purpose, identifier).await?;
        if let Some(value) = &current {
            self.before_database_delete(&DatabaseRecord::Verification(value.clone()))
                .await?;
        }
        if let Some(secondary) = &self.config.secondary_storage {
            for candidate in &candidates {
                secondary.delete(&verification_key(candidate)).await?;
            }
        }
        let mut deleted = None;
        if self.verification_uses_database() {
            for candidate in candidates {
                if let Some(value) = self.store.delete_verification(purpose, &candidate).await? {
                    deleted = Some(value);
                    break;
                }
            }
        } else {
            deleted = current;
        }
        if let Some(value) = &deleted {
            self.after_database_delete(&DatabaseRecord::Verification(value.clone()))
                .await?;
        }
        Ok(deleted)
    }

    /// Replaces an existing verification value and renews its secondary TTL.
    pub async fn update_verification_value(
        &self,
        mut value: VerificationValue,
    ) -> Result<Option<VerificationValue>, AuthError> {
        value.identifier = self
            .processed_verification_identifier(&value.purpose, &value.identifier)
            .await?;
        let value = match self
            .before_database_update(DatabaseRecord::Verification(value))
            .await?
        {
            DatabaseRecord::Verification(value) => value,
            _ => unreachable!("database hook model was validated"),
        };
        let updated = if self.verification_uses_database() {
            self.store.update_verification(value.clone()).await?
        } else if self
            .config
            .secondary_storage
            .as_ref()
            .expect("secondary-only verification storage is configured")
            .get(&verification_key(&value.identifier))
            .await?
            .is_some()
        {
            Some(value)
        } else {
            None
        };
        if let Some(value) = &updated {
            self.cache_verification(value).await?;
            self.after_database_update(&DatabaseRecord::Verification(value.clone()))
                .await?;
        }
        Ok(updated)
    }

    /// Atomically reserves a verification identifier. Secondary-only storage
    /// is rejected because Better Auth requires database uniqueness here.
    pub async fn reserve_verification_value(
        &self,
        mut value: VerificationValue,
    ) -> Result<bool, AuthError> {
        if self.config.secondary_storage.is_some() && !self.config.verification.store_in_database {
            return Err(AuthError::InvalidConfiguration(
                "reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values.".into(),
            ));
        }
        value.identifier = self
            .processed_verification_identifier(&value.purpose, &value.identifier)
            .await?;
        let reserved = self.store.reserve_verification(value.clone()).await?;
        if reserved {
            self.cache_verification(&value).await?;
        }
        Ok(reserved)
    }

    pub(super) async fn verification_identifier_candidates(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<Vec<String>, AuthError> {
        let plain = format!("{purpose}:{identifier}");
        let processed = self.process_identifier(&plain).await?;
        if processed == plain {
            Ok(vec![processed])
        } else {
            Ok(vec![processed, plain])
        }
    }

    async fn processed_verification_identifier(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<String, AuthError> {
        self.verification_identifier_candidates(purpose, identifier)
            .await
            .map(|candidates| candidates[0].clone())
    }

    async fn process_identifier(&self, identifier: &str) -> Result<String, AuthError> {
        let config = &self.config.verification.store_identifier;
        let storage = config
            .overrides
            .iter()
            .find(|(prefix, _)| identifier.starts_with(prefix))
            .map(|(_, storage)| storage)
            .unwrap_or(&config.default);
        match storage {
            VerificationIdentifierStorage::Plain => Ok(identifier.into()),
            VerificationIdentifierStorage::Hashed => {
                Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(identifier.as_bytes())))
            }
            VerificationIdentifierStorage::Custom(hasher) => hasher.hash(identifier).await,
        }
    }

    fn verification_uses_database(&self) -> bool {
        self.config.secondary_storage.is_none() || self.config.verification.store_in_database
    }

    async fn cache_verification(&self, value: &VerificationValue) -> Result<(), AuthError> {
        let Some(secondary) = &self.config.secondary_storage else {
            return Ok(());
        };
        let ttl = (value.expires_at - Utc::now()).num_seconds().max(0) as u64;
        if ttl > 0 {
            secondary
                .set(
                    &verification_key(&value.identifier),
                    serde_json::to_string(value)
                        .map_err(|error| verification_json("write", error))?,
                    Some(ttl),
                )
                .await?;
        }
        Ok(())
    }

    pub(super) async fn clear_cached_verification(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<(), AuthError> {
        let Some(secondary) = &self.config.secondary_storage else {
            return Ok(());
        };
        for candidate in self
            .verification_identifier_candidates(purpose, identifier)
            .await?
        {
            secondary.delete(&verification_key(&candidate)).await?;
        }
        Ok(())
    }
}

fn verification_key(identifier: &str) -> String {
    format!("verification:{identifier}")
}

fn verification_json(operation: &str, error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!(
        "secondary-storage verification JSON {operation} failed: {error}"
    ))
}
