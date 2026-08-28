use super::MemoryStore;
use crate::store::DatabaseCreate;
use crate::{AuthError, VerificationStore, VerificationValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl VerificationStore for MemoryStore {
    async fn create_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<VerificationValue, AuthError> {
        if let Some(transaction) = crate::database_hooks::current_transaction() {
            return match transaction
                .create(crate::DatabaseCreateOperation::Verification(value))
                .await?
            {
                crate::DatabaseRecord::Verification(value) => Ok(value),
                _ => unreachable!("transaction create preserves its model"),
            };
        }
        let mut state = self.state.write().await;
        let (mut value, id) = value.into_parts(self)?;
        value.id = self.create_id("verification", id, state.verifications.len())?;
        if state.verifications.contains_key(&value.id) {
            return Err(AuthError::Storage("verification id already exists".into()));
        }
        state.verifications.insert(value.id.clone(), value.clone());
        Ok(value)
    }

    async fn reserve_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let mut state = self.state.write().await;
        let (mut value, id) = value.into_parts(self)?;
        value.id = self.create_id("verification", id, state.verifications.len())?;
        if state.verifications.contains_key(&value.id) {
            return Ok(None);
        }
        state.verifications.insert(value.id.clone(), value.clone());
        Ok(Some(value))
    }

    async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .verifications
            .values()
            .filter(|value| value.identifier == identifier)
            .max_by_key(|value| value.created_at)
            .cloned())
    }

    async fn consume_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let mut state = self.state.write().await;
        let latest = state
            .verifications
            .values()
            .filter(|value| value.identifier == identifier)
            .max_by_key(|value| value.created_at)
            .map(|value| value.id.clone());
        let Some(latest) = latest else {
            return Ok(None);
        };
        let value = state
            .verifications
            .remove(&latest)
            .expect("latest verification exists");
        state
            .verifications
            .retain(|_, value| value.identifier != identifier);
        Ok(Some(value))
    }

    async fn update_verification(
        &self,
        value: VerificationValue,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let mut state = self.state.write().await;
        if !state.verifications.contains_key(&value.id) {
            return Ok(None);
        }
        state.verifications.insert(value.id.clone(), value.clone());
        Ok(Some(value))
    }

    async fn delete_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let mut state = self.state.write().await;
        let latest = state
            .verifications
            .values()
            .filter(|value| value.identifier == identifier)
            .max_by_key(|value| value.created_at)
            .cloned();
        state
            .verifications
            .retain(|_, value| value.identifier != identifier);
        Ok(latest)
    }

    async fn delete_expired_verifications(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        let mut state = self.state.write().await;
        let before = state.verifications.len();
        state
            .verifications
            .retain(|_, value| value.expires_at >= now);
        Ok((before - state.verifications.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{DatabaseIdInput, DatabaseIdPlan};
    use chrono::Duration;
    use std::sync::Arc;

    fn value(identifier: &str, expires_at: DateTime<Utc>) -> VerificationValue {
        VerificationValue::new(format!("test:{identifier}"), identifier, expires_at)
    }

    fn create(value: VerificationValue) -> DatabaseCreate<VerificationValue> {
        DatabaseCreate::new(
            value,
            DatabaseIdPlan::new(
                crate::DatabaseIdGeneration::Default,
                "verification",
                DatabaseIdInput::Absent,
                false,
            ),
        )
    }

    fn forced(value: VerificationValue) -> DatabaseCreate<VerificationValue> {
        let id = value.identifier.clone();
        DatabaseCreate::new(
            value,
            DatabaseIdPlan::new(
                crate::DatabaseIdGeneration::Default,
                "verification",
                DatabaseIdInput::String(id),
                true,
            ),
        )
    }

    #[tokio::test]
    async fn consumes_once_atomically_and_returns_expired_values() {
        let store = Arc::new(MemoryStore::default());
        let now = Utc::now();
        store
            .create_verification(create(value("live", now + Duration::minutes(1))))
            .await
            .unwrap();
        let (left, right) = tokio::join!(
            store.consume_verification("test:live"),
            store.consume_verification("test:live")
        );
        assert_eq!(
            usize::from(left.unwrap().is_some()) + usize::from(right.unwrap().is_some()),
            1
        );

        store
            .create_verification(create(value("expired", now - Duration::seconds(1))))
            .await
            .unwrap();
        assert_eq!(
            store
                .consume_verification("test:expired")
                .await
                .unwrap()
                .unwrap()
                .identifier,
            "test:expired"
        );
        store
            .create_verification(create(value("cleanup", now - Duration::seconds(1))))
            .await
            .unwrap();
        assert_eq!(store.delete_expired_verifications(now).await.unwrap(), 1);

        store
            .create_verification(create(value("equal", now)))
            .await
            .unwrap();
        assert_eq!(store.delete_expired_verifications(now).await.unwrap(), 0);
        assert!(
            store
                .find_verification("test:equal")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn reservation_is_first_writer_wins_by_supplied_id() {
        let store = Arc::new(MemoryStore::default());
        let expires_at = Utc::now() + Duration::minutes(1);
        let reservation = value("reservation", expires_at);
        let (left, right) = tokio::join!(
            store.reserve_verification(forced(reservation.clone())),
            store.reserve_verification(forced(reservation)),
        );
        assert_eq!(
            usize::from(left.unwrap().is_some()) + usize::from(right.unwrap().is_some()),
            1
        );
    }
}
