use super::AuthService;
use crate::{AuthError, DatabaseCreate, DatabaseRecord, PreparedDatabaseId, VerificationValue};
use chrono::{DateTime, Utc};

mod consume;
mod identifier;

impl AuthService {
    /// Creates one Better Auth verification record. The identifier must already
    /// contain every protocol prefix required by its caller.
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
        value.identifier = self.process_identifier(&value.identifier).await?;
        let value = self.prepare_verification_create(value).await?;
        let value = self.persist_new_verification(value).await?;
        self.cache_verification(&value).await?;
        self.after_database_create(&DatabaseRecord::Verification(value))
            .await
    }

    pub(super) async fn replace_verification_with_create_hooks(
        &self,
        mut value: VerificationValue,
    ) -> Result<(), AuthError> {
        value.identifier = self.process_identifier(&value.identifier).await?;
        let value = self.prepare_verification_create(value).await?;
        let identifier = value.record.identifier.clone();
        let value = if self.verification_uses_database() {
            let existing = self.store.find_verification(&identifier).await?;
            if let Some(mut existing) = existing {
                existing.value = value.record.value.clone();
                existing.expires_at = value.record.expires_at;
                existing.updated_at = Utc::now();
                self.store
                    .update_verification(existing)
                    .await?
                    .ok_or_else(|| {
                        AuthError::Storage("verification disappeared during replacement".into())
                    })?
            } else {
                self.store.create_verification(value).await?
            }
        } else {
            self.materialize_verification(value)?
        };
        self.cache_verification(&value).await?;
        self.after_database_create(&DatabaseRecord::Verification(value))
            .await
    }

    /// Finds the latest Better Auth verification record for one complete
    /// identifier.
    pub async fn find_verification_value(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        self.find_verification_record(identifier, true).await
    }

    pub(super) async fn find_verification_record(
        &self,
        identifier: &str,
        cleanup: bool,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let stored_identifier = self.process_identifier(identifier).await?;
        if let Some(secondary) = &self.config.secondary_storage {
            if let Some(raw) = secondary.get(&verification_key(&stored_identifier)).await?
                && let Ok(value) = serde_json::from_str(&raw)
            {
                return Ok(Some(value));
            }
            if !self.config.verification.store_in_database {
                return Ok(None);
            }
        }
        let found = self.store.find_verification(&stored_identifier).await?;
        if cleanup && !self.config.verification.disable_cleanup {
            self.store.delete_expired_verifications(Utc::now()).await?;
        }
        Ok(found)
    }

    /// Deletes every row for one complete verification identifier.
    pub async fn delete_verification_value(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let stored_identifier = self.process_identifier(identifier).await?;
        let current = self.lookup_stored_verification(&stored_identifier).await?;
        if let Some(value) = &current {
            self.before_database_delete(&DatabaseRecord::Verification(value.clone()))
                .await?;
        }
        if let Some(secondary) = &self.config.secondary_storage {
            secondary
                .delete(&verification_key(&stored_identifier))
                .await?;
        }
        let deleted = if self.verification_uses_database() {
            self.store.delete_verification(&stored_identifier).await?
        } else {
            current
        };
        if let Some(value) = &deleted {
            self.after_database_delete(&DatabaseRecord::Verification(value.clone()))
                .await?;
        }
        Ok(deleted)
    }

    /// Updates the latest row selected by one complete identifier.
    pub async fn update_verification_value(
        &self,
        identifier: &str,
        value: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let stored_identifier = self.process_identifier(identifier).await?;
        let Some(mut candidate) = self.lookup_stored_verification(&stored_identifier).await? else {
            return Ok(None);
        };
        candidate.value = value;
        if let Some(expires_at) = expires_at {
            candidate.expires_at = expires_at;
        }
        candidate.updated_at = Utc::now();
        let candidate = match self
            .before_database_update(DatabaseRecord::Verification(candidate))
            .await?
        {
            DatabaseRecord::Verification(value) => value,
            _ => unreachable!("database hook model was validated"),
        };
        let updated = if self.verification_uses_database() {
            self.store.update_verification(candidate.clone()).await?
        } else {
            Some(candidate)
        };
        if let Some(value) = &updated {
            self.cache_verification(value).await?;
            self.after_database_update(&DatabaseRecord::Verification(value.clone()))
                .await?;
        }
        Ok(updated)
    }

    async fn lookup_stored_verification(
        &self,
        stored_identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        if let Some(secondary) = &self.config.secondary_storage {
            if let Some(raw) = secondary.get(&verification_key(stored_identifier)).await? {
                return serde_json::from_str(&raw)
                    .map(Some)
                    .map_err(|error| verification_json("read", error));
            }
            if !self.config.verification.store_in_database {
                return Ok(None);
            }
        }
        self.store.find_verification(stored_identifier).await
    }

    fn verification_uses_database(&self) -> bool {
        self.config.secondary_storage.is_none() || self.config.verification.store_in_database
    }

    async fn persist_new_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<VerificationValue, AuthError> {
        if self.verification_uses_database() {
            self.store.create_verification(value).await
        } else {
            self.materialize_verification(value)
        }
    }

    fn materialize_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<VerificationValue, AuthError> {
        let mut record = value.record;
        record.id = match value.id.prepare(self.store.as_ref())? {
            PreparedDatabaseId::Value(value) => value.into_output_string(),
            PreparedDatabaseId::Deferred | PreparedDatabaseId::DeferredSerial => {
                return Err(AuthError::Storage(
                    "verification ID generation was deferred without database storage".into(),
                ));
            }
        };
        Ok(record)
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
}

pub(super) fn verification_key(identifier: &str) -> String {
    format!("verification:{identifier}")
}

fn verification_json(operation: &str, error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!(
        "secondary-storage verification JSON {operation} failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore, VerificationIdentifierStorage, VerificationStore};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Duration;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn create(value: VerificationValue) -> DatabaseCreate<VerificationValue> {
        DatabaseCreate::new(
            value,
            crate::DatabaseIdPlan::new(
                crate::DatabaseIdGeneration::Default,
                "verification",
                crate::DatabaseIdInput::Absent,
                false,
            ),
        )
    }

    #[tokio::test]
    async fn deletion_targets_only_the_processed_identifier() {
        let store = Arc::new(MemoryStore::default());
        let mut config = AuthConfig::new([23; 32]).unwrap();
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        let service = AuthService::new(store.clone(), config);
        let expires_at = Utc::now() + Duration::minutes(1);
        let processed = URL_SAFE_NO_PAD.encode(Sha256::digest(b"plain"));
        store
            .create_verification(create(VerificationValue::new(
                processed.clone(),
                "processed",
                expires_at,
            )))
            .await
            .unwrap();
        store
            .create_verification(create(VerificationValue::new("plain", "plain", expires_at)))
            .await
            .unwrap();

        service.delete_verification_value("plain").await.unwrap();

        assert!(store.find_verification(&processed).await.unwrap().is_none());
        assert!(store.find_verification("plain").await.unwrap().is_some());
    }
}
