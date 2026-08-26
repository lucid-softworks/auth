use super::{
    DeviceAuthorizationStore, DeviceCode, DeviceCodeCreateOutcome, DeviceCodeOwner,
    DeviceCodeStatus,
};
use crate::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Default)]
pub struct MemoryDeviceAuthorizationStore {
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    records: HashMap<Uuid, DeviceCode>,
    by_device_code: HashMap<String, Uuid>,
    by_user_code: HashMap<String, Uuid>,
}

impl MemoryDeviceAuthorizationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DeviceAuthorizationStore for MemoryDeviceAuthorizationStore {
    async fn create_device_code(
        &self,
        code: DeviceCode,
    ) -> Result<DeviceCodeCreateOutcome, AuthError> {
        let mut state = self.state.write().await;
        if state.records.contains_key(&code.id)
            || state.by_device_code.contains_key(&code.device_code)
            || state.by_user_code.contains_key(&code.user_code)
        {
            return Ok(DeviceCodeCreateOutcome::UniqueConflict);
        }
        state
            .by_device_code
            .insert(code.device_code.clone(), code.id);
        state.by_user_code.insert(code.user_code.clone(), code.id);
        state.records.insert(code.id, code.clone());
        Ok(DeviceCodeCreateOutcome::Created(code))
    }

    async fn find_device_code(&self, device_code: &str) -> Result<Option<DeviceCode>, AuthError> {
        let state = self.state.read().await;
        Ok(state
            .by_device_code
            .get(device_code)
            .and_then(|id| state.records.get(id))
            .cloned())
    }

    async fn find_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let state = self.state.read().await;
        Ok(state
            .by_user_code
            .get(user_code)
            .and_then(|id| state.records.get(id))
            .cloned())
    }

    async fn bind_pending_user(
        &self,
        id: Uuid,
        user_id: &str,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let mut state = self.state.write().await;
        let Some(record) = state.records.get_mut(&id) else {
            return Ok(None);
        };
        if record.status != DeviceCodeStatus::Pending || record.user_id.is_some() {
            return Ok(None);
        }
        record.user_id = Some(user_id.to_owned());
        Ok(Some(record.clone()))
    }

    async fn update_last_polled_at(
        &self,
        id: Uuid,
        polled_at: DateTime<Utc>,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let mut state = self.state.write().await;
        let Some(record) = state.records.get_mut(&id) else {
            return Ok(None);
        };
        record.last_polled_at = Some(polled_at);
        Ok(Some(record.clone()))
    }

    async fn update_device_code_status(
        &self,
        id: Uuid,
        status: DeviceCodeStatus,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let mut state = self.state.write().await;
        let Some(record) = state.records.get_mut(&id) else {
            return Ok(None);
        };
        record.status = status;
        Ok(Some(record.clone()))
    }

    async fn delete_device_code(&self, id: Uuid) -> Result<Option<DeviceCode>, AuthError> {
        let mut state = self.state.write().await;
        Ok(remove_record(&mut state, id))
    }

    async fn consume_approved_device_code(
        &self,
        id: Uuid,
        owner: DeviceCodeOwner,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let mut state = self.state.write().await;
        let consumable = state.records.get(&id).is_some_and(|record| {
            record.status == DeviceCodeStatus::Approved && owner.matches(record)
        });
        Ok(consumable
            .then(|| remove_record(&mut state, id).expect("consumable device code exists")))
    }
}

fn remove_record(state: &mut State, id: Uuid) -> Option<DeviceCode> {
    let record = state.records.remove(&id)?;
    state.by_device_code.remove(&record.device_code);
    state.by_user_code.remove(&record.user_code);
    Some(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::sync::Arc;

    #[tokio::test]
    async fn binds_an_unclaimed_pending_record_once() {
        let store = Arc::new(MemoryDeviceAuthorizationStore::new());
        let record = record();
        store.create_device_code(record.clone()).await.unwrap();
        let first_user = Uuid::new_v4().to_string();
        let second_user = Uuid::new_v4().to_string();
        let (first, second) = tokio::join!(
            store.bind_pending_user(record.id, &first_user),
            store.bind_pending_user(record.id, &second_user)
        );
        let winners = [first.unwrap(), second.unwrap()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(winners.len(), 1);
        assert!(
            matches!(winners[0].user_id.as_deref(), Some(id) if id == first_user || id == second_user)
        );
    }

    #[tokio::test]
    async fn consumes_an_approved_client_owned_record_once() {
        let store = Arc::new(MemoryDeviceAuthorizationStore::new());
        let mut record = record();
        record.status = DeviceCodeStatus::Approved;
        store.create_device_code(record.clone()).await.unwrap();
        assert!(
            store
                .consume_approved_device_code(record.id, DeviceCodeOwner::ClientId("other".into()))
                .await
                .unwrap()
                .is_none()
        );
        let (first, second) = tokio::join!(
            store.consume_approved_device_code(
                record.id,
                DeviceCodeOwner::ClientId("client".into())
            ),
            store.consume_approved_device_code(
                record.id,
                DeviceCodeOwner::ClientId("client".into())
            )
        );
        assert_eq!(
            usize::from(first.unwrap().is_some()) + usize::from(second.unwrap().is_some()),
            1
        );
    }

    #[tokio::test]
    async fn consume_uses_the_selected_owner_field() {
        let store = MemoryDeviceAuthorizationStore::new();
        let mut record = record();
        record.status = DeviceCodeStatus::Approved;
        record.oauth_client_id = Some("oauth-client".into());
        store.create_device_code(record.clone()).await.unwrap();
        assert!(
            store
                .consume_approved_device_code(
                    record.id,
                    DeviceCodeOwner::OAuthClientId("client".into())
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .consume_approved_device_code(
                    record.id,
                    DeviceCodeOwner::OAuthClientId("oauth-client".into())
                )
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn decision_and_poll_writes_are_ordinary_updates() {
        let store = MemoryDeviceAuthorizationStore::new();
        let record = record();
        store.create_device_code(record.clone()).await.unwrap();
        let polled_at = Utc::now();
        assert_eq!(
            store
                .update_last_polled_at(record.id, polled_at)
                .await
                .unwrap()
                .unwrap()
                .last_polled_at,
            Some(polled_at)
        );
        assert_eq!(
            store
                .update_device_code_status(record.id, DeviceCodeStatus::Denied)
                .await
                .unwrap()
                .unwrap()
                .status,
            DeviceCodeStatus::Denied
        );
    }

    fn record() -> DeviceCode {
        DeviceCode {
            id: Uuid::new_v4(),
            device_code: "device".into(),
            user_code: "USERCODE".into(),
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(30),
            status: DeviceCodeStatus::Pending,
            last_polled_at: None,
            polling_interval: Some(5_000.0),
            client_id: Some("client".into()),
            scope: None,
            resources: None,
            oauth_client_id: None,
        }
    }
}
