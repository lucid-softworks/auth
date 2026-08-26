use super::{AuthService, verification_key};
use crate::{AuthError, DatabaseRecord, VerificationValue};
use chrono::{DateTime, Utc};

impl AuthService {
    pub(in crate::service) async fn consume_verification_record(
        &self,
        identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let stored_identifier = self.process_identifier(identifier).await?;
        if let Some(secondary) = &self.config.secondary_storage
            && !self.config.verification.store_in_database
        {
            let Some(raw) = secondary
                .get_and_delete(&verification_key(&stored_identifier))
                .await?
            else {
                return Ok(None);
            };
            let Ok(value) = serde_json::from_str::<VerificationValue>(&raw) else {
                return Ok(None);
            };
            return Ok((value.expires_at >= now).then_some(value));
        }
        let current = self.store.find_verification(&stored_identifier).await?;
        if let Some(candidate) = &current {
            self.before_database_delete(&DatabaseRecord::Verification(candidate.clone()))
                .await?;
        }
        let consumed = self.store.consume_verification(&stored_identifier).await?;
        if consumed.is_some()
            && let Some(secondary) = &self.config.secondary_storage
        {
            secondary
                .delete(&verification_key(&stored_identifier))
                .await?;
        }
        if let Some(value) = &consumed {
            self.after_database_delete(&DatabaseRecord::Verification(value.clone()))
                .await?;
        }
        Ok(consumed.filter(|value| value.expires_at >= now))
    }

    /// Atomically consumes one unexpired Better Auth verification record.
    pub async fn consume_verification_value(
        &self,
        identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        self.consume_verification_record(identifier, now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, MemorySecondaryStorage, MemoryStore, SecondaryStorage,
        VerificationIdentifierStorage, VerificationStore,
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Duration;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn create(value: VerificationValue) -> crate::DatabaseCreate<VerificationValue> {
        crate::DatabaseCreate::new(
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
    async fn non_plain_lookup_and_consume_never_read_the_plain_alias() {
        let store = Arc::new(MemoryStore::default());
        let mut config = AuthConfig::new([21; 32]).unwrap();
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        let service = AuthService::new(store.clone(), config);
        let expires_at = Utc::now() + Duration::minutes(1);
        store
            .create_verification(create(VerificationValue::new("plain", "value", expires_at)))
            .await
            .unwrap();
        assert!(
            service
                .find_verification_value("plain")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            service
                .consume_verification_value("plain", Utc::now())
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.find_verification("plain").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn processed_identifier_is_the_only_database_candidate() {
        let store = Arc::new(MemoryStore::default());
        let mut config = AuthConfig::new([24; 32]).unwrap();
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        let service = AuthService::new(store.clone(), config);
        let now = Utc::now();
        let processed = URL_SAFE_NO_PAD.encode(Sha256::digest(b"plain"));
        store
            .create_verification(create(VerificationValue::new(
                processed.clone(),
                "processed",
                now + Duration::minutes(1),
            )))
            .await
            .unwrap();
        store
            .create_verification(create(VerificationValue::new(
                "plain",
                "alias",
                now + Duration::minutes(1),
            )))
            .await
            .unwrap();
        assert_eq!(
            service
                .consume_verification_value("plain", now)
                .await
                .unwrap()
                .unwrap()
                .value,
            "processed"
        );
        assert!(store.find_verification(&processed).await.unwrap().is_none());
        assert!(store.find_verification("plain").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn secondary_only_consumes_only_the_processed_key() {
        let secondary = Arc::new(MemorySecondaryStorage::default());
        let mut config = AuthConfig::new([22; 32]).unwrap();
        config.secondary_storage = Some(secondary.clone());
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        config.verification.store_in_database = false;
        let service = AuthService::new(Arc::new(MemoryStore::default()), config);
        let value = VerificationValue::new("plain", "value", Utc::now() + Duration::minutes(1));
        let processed = URL_SAFE_NO_PAD.encode(Sha256::digest(b"plain"));
        service.create_verification_value(value).await.unwrap();
        secondary
            .set(
                "verification:plain",
                serde_json::to_string(&VerificationValue::new(
                    "plain",
                    "alias",
                    Utc::now() + Duration::minutes(1),
                ))
                .unwrap(),
                Some(60),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .consume_verification_value("plain", Utc::now())
                .await
                .unwrap()
                .unwrap()
                .value,
            "value"
        );
        assert!(secondary.get("verification:plain").await.unwrap().is_some());
        assert!(
            secondary
                .get(&format!("verification:{processed}"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn malformed_secondary_processed_value_does_not_read_plain() {
        let secondary = Arc::new(MemorySecondaryStorage::default());
        let mut config = AuthConfig::new([25; 32]).unwrap();
        config.secondary_storage = Some(secondary.clone());
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        config.verification.store_in_database = false;
        let service = AuthService::new(Arc::new(MemoryStore::default()), config);
        let value = VerificationValue::new("plain", "alias", Utc::now() + Duration::minutes(1));
        let processed = URL_SAFE_NO_PAD.encode(Sha256::digest(b"plain"));
        secondary
            .set(
                &format!("verification:{processed}"),
                "not-json".into(),
                Some(60),
            )
            .await
            .unwrap();
        secondary
            .set(
                "verification:plain",
                serde_json::to_string(&value).unwrap(),
                Some(60),
            )
            .await
            .unwrap();
        assert!(
            service
                .consume_verification_value("plain", Utc::now())
                .await
                .unwrap()
                .is_none()
        );
        assert!(secondary.get("verification:plain").await.unwrap().is_some());
    }
}
