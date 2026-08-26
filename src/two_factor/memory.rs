use super::{TwoFactorRecord, TwoFactorStore};
use crate::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct MemoryTwoFactorStore {
    records: Arc<RwLock<HashMap<Uuid, TwoFactorRecord>>>,
    enabled_users: Arc<RwLock<HashSet<Uuid>>>,
}

#[async_trait]
impl TwoFactorStore for MemoryTwoFactorStore {
    async fn two_factor_enabled(&self, user_id: Uuid) -> Result<bool, AuthError> {
        Ok(self.enabled_users.read().await.contains(&user_id))
    }

    async fn set_two_factor_enabled(&self, user_id: Uuid, enabled: bool) -> Result<(), AuthError> {
        let mut users = self.enabled_users.write().await;
        if enabled {
            users.insert(user_id);
        } else {
            users.remove(&user_id);
        }
        Ok(())
    }

    async fn find_two_factor(&self, user_id: Uuid) -> Result<Option<TwoFactorRecord>, AuthError> {
        Ok(self.records.read().await.get(&user_id).cloned())
    }

    async fn upsert_two_factor(
        &self,
        record: TwoFactorRecord,
    ) -> Result<TwoFactorRecord, AuthError> {
        self.records
            .write()
            .await
            .insert(record.user_id, record.clone());
        Ok(record)
    }

    async fn delete_two_factor(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.records.write().await.remove(&user_id);
        self.enabled_users.write().await.remove(&user_id);
        Ok(())
    }

    async fn replace_backup_codes(
        &self,
        user_id: Uuid,
        expected: &str,
        replacement: String,
    ) -> Result<bool, AuthError> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(&user_id) else {
            return Ok(false);
        };
        if record.encrypted_backup_codes != expected {
            return Ok(false);
        }
        record.encrypted_backup_codes = replacement;
        Ok(true)
    }

    async fn complete_two_factor_enrollment(&self, user_id: Uuid) -> Result<bool, AuthError> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(&user_id) else {
            return Ok(false);
        };
        record.verified = true;
        self.enabled_users.write().await.insert(user_id);
        Ok(true)
    }

    async fn record_two_factor_failure(
        &self,
        user_id: Uuid,
        max_attempts: u32,
        locked_until: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(&user_id) else {
            return Ok(false);
        };
        record.failed_verification_count = record.failed_verification_count.saturating_add(1);
        let locked = record.failed_verification_count >= max_attempts;
        if locked {
            record.locked_until = Some(locked_until);
        }
        Ok(locked)
    }

    async fn reset_two_factor_failures(&self, user_id: Uuid) -> Result<(), AuthError> {
        if let Some(record) = self.records.write().await.get_mut(&user_id) {
            record.failed_verification_count = 0;
            record.locked_until = None;
        }
        Ok(())
    }
}
