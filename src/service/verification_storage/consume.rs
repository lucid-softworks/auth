use super::{AuthService, verification_key};
use crate::{AuthError, DatabaseRecord, VerificationValue};
use chrono::{DateTime, Utc};

impl AuthService {
    pub(in crate::service) async fn consume_verification_record(
        &self,
        identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let identifiers = self.verification_identifiers(identifier).await?;
        if let Some(secondary) = &self.config.secondary_storage
            && !self.config.verification.store_in_database
        {
            for stored_identifier in &identifiers {
                let Some(raw) = secondary
                    .get_and_delete(&verification_key(stored_identifier))
                    .await?
                else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<VerificationValue>(&raw) else {
                    continue;
                };
                for alternate in identifiers
                    .iter()
                    .filter(|value| *value != stored_identifier)
                {
                    secondary.delete(&verification_key(alternate)).await?;
                }
                return Ok((value.expires_at >= now).then_some(value));
            }
            return Ok(None);
        }
        let mut current = None;
        for stored_identifier in &identifiers {
            if let Some(value) = self.store.find_verification(stored_identifier).await? {
                current = Some(value);
                break;
            }
        }
        if let Some(candidate) = &current {
            self.before_database_delete(&DatabaseRecord::Verification(candidate.clone()))
                .await?;
        }
        let mut consumed = None;
        for stored_identifier in &identifiers {
            if let Some(value) = self.store.consume_verification(stored_identifier).await? {
                consumed = Some(value);
                break;
            }
        }
        if consumed.is_some()
            && let Some(secondary) = &self.config.secondary_storage
        {
            for stored_identifier in &identifiers {
                secondary
                    .delete(&verification_key(stored_identifier))
                    .await?;
            }
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

    #[tokio::test]
    async fn non_plain_lookup_and_consume_fall_back_to_plain() {
        let store = Arc::new(MemoryStore::default());
        let mut config = AuthConfig::new([21; 32]).unwrap();
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        let service = AuthService::new(store.clone(), config);
        let expires_at = Utc::now() + Duration::minutes(1);
        store
            .create_verification(VerificationValue::new("plain", "value", expires_at))
            .await
            .unwrap();
        assert_eq!(
            service
                .find_verification_value("plain")
                .await
                .unwrap()
                .unwrap()
                .value,
            "value"
        );
        assert!(
            service
                .consume_verification_value("plain", Utc::now())
                .await
                .unwrap()
                .is_some()
        );
        assert!(store.find_verification("plain").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_processed_winner_leaves_live_plain_fallback() {
        let store = Arc::new(MemoryStore::default());
        let mut config = AuthConfig::new([24; 32]).unwrap();
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        let service = AuthService::new(store.clone(), config);
        let now = Utc::now();
        let processed = URL_SAFE_NO_PAD.encode(Sha256::digest(b"plain"));
        store
            .create_verification(VerificationValue::new(
                processed.clone(),
                "expired",
                now - Duration::seconds(1),
            ))
            .await
            .unwrap();
        store
            .create_verification(VerificationValue::new(
                "plain",
                "live",
                now + Duration::minutes(1),
            ))
            .await
            .unwrap();
        assert!(
            service
                .consume_verification_value("plain", now)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.find_verification(&processed).await.unwrap().is_none());
        assert!(store.find_verification("plain").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn secondary_fallback_invalidates_both_cache_keys() {
        let secondary = Arc::new(MemorySecondaryStorage::default());
        let mut config = AuthConfig::new([22; 32]).unwrap();
        config.secondary_storage = Some(secondary.clone());
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        let service = AuthService::new(Arc::new(MemoryStore::default()), config);
        let value = VerificationValue::new("plain", "value", Utc::now() + Duration::minutes(1));
        let processed = URL_SAFE_NO_PAD.encode(Sha256::digest(b"plain"));
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
                .is_some()
        );
        assert!(secondary.get("verification:plain").await.unwrap().is_none());
        assert!(
            secondary
                .get(&format!("verification:{processed}"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn malformed_secondary_processed_value_falls_back_to_live_plain() {
        let secondary = Arc::new(MemorySecondaryStorage::default());
        let mut config = AuthConfig::new([25; 32]).unwrap();
        config.secondary_storage = Some(secondary.clone());
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
        let service = AuthService::new(Arc::new(MemoryStore::default()), config);
        let value = VerificationValue::new("plain", "live", Utc::now() + Duration::minutes(1));
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
        assert_eq!(
            service
                .consume_verification_value("plain", Utc::now())
                .await
                .unwrap()
                .unwrap()
                .value,
            "live"
        );
    }
}
