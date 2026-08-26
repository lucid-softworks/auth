use super::AuthService;
use crate::{AuthError, VerificationIdentifierStorage, VerificationValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

impl AuthService {
    /// Atomically reserves an identifier using a deterministic primary key.
    pub async fn reserve_verification_value(
        &self,
        mut value: VerificationValue,
    ) -> Result<bool, AuthError> {
        if self.config.secondary_storage.is_some() && !self.config.verification.store_in_database {
            return Err(AuthError::InvalidConfiguration(
                "reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values.".into(),
            ));
        }
        value.id = reservation_id(&value.identifier);
        value.identifier = self.process_identifier(&value.identifier).await?;
        let reserved = self.store.reserve_verification(value.clone()).await?;
        if reserved {
            self.cache_verification(&value).await?;
        }
        Ok(reserved)
    }

    pub(super) async fn process_identifier(&self, identifier: &str) -> Result<String, AuthError> {
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
}

fn reservation_id(identifier: &str) -> uuid::Uuid {
    let digest = Sha256::digest(format!("reserve:{identifier}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, MemoryStore, VerificationIdentifierHasher, VerificationIdentifierStorage,
        VerificationValue,
    };
    use chrono::{Duration, Utc};
    use std::sync::Arc;

    #[derive(Debug)]
    struct CollidingHasher;

    #[async_trait::async_trait]
    impl VerificationIdentifierHasher for CollidingHasher {
        async fn hash(&self, _identifier: &str) -> Result<String, AuthError> {
            Ok("collision".into())
        }
    }

    #[test]
    fn reservations_have_stable_original_identifier_keys() {
        assert_eq!(reservation_id("one"), reservation_id("one"));
        assert_ne!(reservation_id("one"), reservation_id("two"));
    }

    #[tokio::test]
    async fn reservation_ids_are_derived_before_identifier_processing() {
        let store = Arc::new(MemoryStore::default());
        let mut config = AuthConfig::new([20; 32]).unwrap();
        config.verification.store_identifier.default =
            VerificationIdentifierStorage::Custom(Arc::new(CollidingHasher));
        let service = AuthService::new(store, config);
        let expires_at = Utc::now() + Duration::minutes(1);

        assert!(
            service
                .reserve_verification_value(VerificationValue::new("one", "one", expires_at))
                .await
                .unwrap()
        );
        assert!(
            service
                .reserve_verification_value(VerificationValue::new("two", "two", expires_at))
                .await
                .unwrap()
        );
        assert!(
            !service
                .reserve_verification_value(VerificationValue::new("one", "again", expires_at))
                .await
                .unwrap()
        );
    }
}
