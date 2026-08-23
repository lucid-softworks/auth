use super::MemoryStore;
use crate::{AuthError, VerificationStore, VerificationValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl VerificationStore for MemoryStore {
    async fn create_verification(&self, value: VerificationValue) -> Result<(), AuthError> {
        let key = (value.purpose.clone(), value.identifier.clone());
        let mut state = self.state.write().await;
        if state.verifications.contains_key(&key) {
            return Err(AuthError::Storage(
                "verification identifier already exists".into(),
            ));
        }
        state.verifications.insert(key, value);
        Ok(())
    }

    async fn find_verification(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .verifications
            .get(&(purpose.to_owned(), identifier.to_owned()))
            .cloned())
    }

    async fn consume_verification(
        &self,
        purpose: &str,
        identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let key = (purpose.to_owned(), identifier.to_owned());
        let mut state = self.state.write().await;
        let Some(value) = state.verifications.remove(&key) else {
            return Ok(None);
        };
        Ok((value.expires_at > now).then_some(value))
    }

    async fn delete_expired_verifications(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        let mut state = self.state.write().await;
        let before = state.verifications.len();
        state
            .verifications
            .retain(|_, value| value.expires_at > now);
        Ok((before - state.verifications.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;
    use std::sync::Arc;

    fn value(identifier: &str, expires_at: DateTime<Utc>) -> VerificationValue {
        VerificationValue {
            purpose: "test".into(),
            identifier: identifier.into(),
            payload: json!({ "value": identifier }),
            expires_at,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn consumes_once_atomically_and_rejects_expired_values() {
        let store = Arc::new(MemoryStore::default());
        let now = Utc::now();
        store
            .create_verification(value("live", now + Duration::minutes(1)))
            .await
            .unwrap();
        let (left, right) = tokio::join!(
            store.consume_verification("test", "live", now),
            store.consume_verification("test", "live", now)
        );
        assert_eq!(
            usize::from(left.unwrap().is_some()) + usize::from(right.unwrap().is_some()),
            1
        );

        store
            .create_verification(value("expired", now - Duration::seconds(1)))
            .await
            .unwrap();
        assert!(
            store
                .consume_verification("test", "expired", now)
                .await
                .unwrap()
                .is_none()
        );
        store
            .create_verification(value("cleanup", now - Duration::seconds(1)))
            .await
            .unwrap();
        assert_eq!(store.delete_expired_verifications(now).await.unwrap(), 1);
    }
}
