use super::{TwoFactorRecord, TwoFactorStore};
use crate::{AuthError, DatabaseIdSupplier, PreparedDatabaseId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct MemoryTwoFactorStore {
    records: Arc<RwLock<HashMap<String, TwoFactorRecord>>>,
    enabled_users: Arc<RwLock<HashSet<String>>>,
    next_serial_id: Arc<AtomicU64>,
}

#[async_trait]
impl TwoFactorStore for MemoryTwoFactorStore {
    async fn two_factor_enabled(&self, user_id: &str) -> Result<bool, AuthError> {
        Ok(self.enabled_users.read().await.contains(user_id))
    }

    async fn set_two_factor_enabled(&self, user_id: &str, enabled: bool) -> Result<(), AuthError> {
        let mut users = self.enabled_users.write().await;
        if enabled {
            users.insert(user_id.to_owned());
        } else {
            users.remove(user_id);
        }
        Ok(())
    }

    async fn find_two_factor(&self, user_id: &str) -> Result<Option<TwoFactorRecord>, AuthError> {
        Ok(self.records.read().await.get(user_id).cloned())
    }

    async fn upsert_two_factor(
        &self,
        id: &dyn DatabaseIdSupplier,
        mut record: TwoFactorRecord,
    ) -> Result<TwoFactorRecord, AuthError> {
        let mut records = self.records.write().await;
        if let Some(existing) = records.get(&record.user_id) {
            record.id = existing.id.clone();
            records.insert(record.user_id.clone(), record.clone());
            return Ok(record);
        }
        record.id = match id.prepare()? {
            PreparedDatabaseId::Value(value) => value.into_output_string(),
            PreparedDatabaseId::DeferredSerial => self
                .next_serial_id
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1)
                .to_string(),
            PreparedDatabaseId::Deferred => {
                return Err(AuthError::Storage(
                    "database adapter did not return an id for model 'twoFactor'".into(),
                ));
            }
        };
        records.insert(record.user_id.clone(), record.clone());
        Ok(record)
    }

    async fn delete_two_factor(&self, user_id: &str) -> Result<(), AuthError> {
        self.records.write().await.remove(user_id);
        self.enabled_users.write().await.remove(user_id);
        Ok(())
    }

    async fn replace_backup_codes(
        &self,
        user_id: &str,
        expected: &str,
        replacement: String,
    ) -> Result<bool, AuthError> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(user_id) else {
            return Ok(false);
        };
        if record.encrypted_backup_codes != expected {
            return Ok(false);
        }
        record.encrypted_backup_codes = replacement;
        Ok(true)
    }

    async fn complete_two_factor_enrollment(&self, user_id: &str) -> Result<bool, AuthError> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(user_id) else {
            return Ok(false);
        };
        record.verified = true;
        self.enabled_users.write().await.insert(user_id.to_owned());
        Ok(true)
    }

    async fn record_two_factor_failure(
        &self,
        user_id: &str,
        max_attempts: u32,
        locked_until: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(user_id) else {
            return Ok(false);
        };
        record.failed_verification_count = record.failed_verification_count.saturating_add(1);
        let locked = record.failed_verification_count >= max_attempts;
        if locked {
            record.locked_until = Some(locked_until);
        }
        Ok(locked)
    }

    async fn reset_two_factor_failures(&self, user_id: &str) -> Result<(), AuthError> {
        if let Some(record) = self.records.write().await.get_mut(user_id) {
            record.failed_verification_count = 0;
            record.locked_until = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthStore, DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
        DatabaseIdGenerationSize, DatabaseIdGenerator, DatabaseIdInput, DatabaseIdPlan,
        MemoryStore,
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug, Default)]
    struct CallbackLedger {
        calls: Mutex<Vec<(String, DatabaseIdGenerationSize)>>,
    }

    impl DatabaseIdGenerator for CallbackLedger {
        fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            self.calls
                .lock()
                .unwrap()
                .push((request.model.into(), request.size));
            DatabaseIdGenerationResult::Id("opaque::two-factor::?/+".into())
        }
    }

    #[derive(Debug)]
    struct CountingCallback(Arc<AtomicUsize>);

    impl DatabaseIdGenerator for CountingCallback {
        fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            self.0.fetch_add(1, Ordering::SeqCst);
            DatabaseIdGenerationResult::Id("must-not-be-consumed".into())
        }
    }

    fn record(user_id: &str) -> TwoFactorRecord {
        TwoFactorRecord {
            id: String::new(),
            user_id: user_id.into(),
            encrypted_secret: "encrypted-secret".into(),
            encrypted_backup_codes: "encrypted-codes".into(),
            verified: false,
            failed_verification_count: 0,
            locked_until: None,
        }
    }

    async fn insert(
        store: &MemoryTwoFactorStore,
        auth: &dyn AuthStore,
        strategy: DatabaseIdGeneration,
        user_id: &str,
    ) -> Result<TwoFactorRecord, AuthError> {
        let plan = DatabaseIdPlan::new(strategy, "twoFactor", DatabaseIdInput::Absent, false);
        store
            .upsert_two_factor(&|| plan.prepare(auth), record(user_id))
            .await
    }

    #[tokio::test]
    async fn application_and_serial_strategies_return_public_string_ids() {
        let auth = MemoryStore::default();
        let default_store = MemoryTwoFactorStore::default();
        let generated = insert(
            &default_store,
            &auth,
            DatabaseIdGeneration::Default,
            "arbitrary-user",
        )
        .await
        .unwrap();
        assert_eq!(generated.id.len(), 32);
        assert!(
            generated
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        );

        let serial_store = MemoryTwoFactorStore::default();
        for (user_id, expected) in [("first-user", "1"), ("second-user", "2")] {
            assert_eq!(
                insert(&serial_store, &auth, DatabaseIdGeneration::Serial, user_id)
                    .await
                    .unwrap()
                    .id,
                expected
            );
        }

        let uuid_store = MemoryTwoFactorStore::default();
        let generated = insert(&uuid_store, &auth, DatabaseIdGeneration::Uuid, "uuid-user")
            .await
            .unwrap();
        uuid::Uuid::parse_str(&generated.id).unwrap();
    }

    #[tokio::test]
    async fn callback_receives_the_canonical_model_once_on_insert_only() {
        let auth = MemoryStore::default();
        let store = MemoryTwoFactorStore::default();
        let ledger = Arc::new(CallbackLedger::default());
        let inserted = insert(
            &store,
            &auth,
            DatabaseIdGeneration::Callback(ledger.clone()),
            "callback-user",
        )
        .await
        .unwrap();
        assert_eq!(inserted.id, "opaque::two-factor::?/+");
        assert_eq!(
            ledger.calls.lock().unwrap().as_slice(),
            &[("twoFactor".into(), DatabaseIdGenerationSize::Omitted)]
        );

        let update_calls = Arc::new(AtomicUsize::new(0));
        let update_plan = DatabaseIdPlan::new(
            DatabaseIdGeneration::Callback(Arc::new(CountingCallback(update_calls.clone()))),
            "twoFactor",
            DatabaseIdInput::Absent,
            false,
        );
        let mut update = record("callback-user");
        update.id = "ignored-input-id".into();
        update.encrypted_secret = "replacement-secret".into();
        let updated = store
            .upsert_two_factor(&|| update_plan.prepare(&auth), update)
            .await
            .unwrap();
        assert_eq!(update_calls.load(Ordering::SeqCst), 0);
        assert_eq!(updated.id, inserted.id);
        assert_eq!(updated.encrypted_secret, "replacement-secret");
    }

    #[tokio::test]
    async fn database_generation_is_an_explicit_memory_adapter_misconfiguration() {
        let auth = MemoryStore::default();
        let store = MemoryTwoFactorStore::default();
        let error = insert(
            &store,
            &auth,
            DatabaseIdGeneration::Database,
            "database-user",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            AuthError::Storage(message)
                if message == "database adapter did not return an id for model 'twoFactor'"
        ));
        assert!(
            store
                .find_two_factor("database-user")
                .await
                .unwrap()
                .is_none()
        );
    }
}
