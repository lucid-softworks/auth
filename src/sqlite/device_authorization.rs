use super::{SqliteFilter, SqliteStore, codec};
use crate::{
    AuthError, AuthStore, DatabaseCreate, DeviceAuthorizationStore, DeviceCode,
    DeviceCodeCreateOutcome, DeviceCodeOwner, DeviceCodeStatus,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl DeviceAuthorizationStore for SqliteStore {
    async fn create_device_code(
        &self,
        code: DatabaseCreate<DeviceCode>,
        auth_store: &dyn AuthStore,
    ) -> Result<DeviceCodeCreateOutcome, AuthError> {
        if self
            .find_device_code(&code.record.device_code)
            .await?
            .is_some()
            || self
                .find_device_code_by_user_code(&code.record.user_code)
                .await?
                .is_some()
        {
            return Ok(DeviceCodeCreateOutcome::UniqueConflict);
        }
        let id = code.id.prepare(auth_store)?;
        let record = codec::create_record(self, "deviceCode", &code.record, &id)?;
        match self.insert_record("deviceCode", record).await {
            Ok(record) => codec::decode("deviceCode", record).map(DeviceCodeCreateOutcome::Created),
            Err(AuthError::Storage(message)) if message.contains("UNIQUE constraint failed") => {
                Ok(DeviceCodeCreateOutcome::UniqueConflict)
            }
            Err(error) => Err(error),
        }
    }

    async fn find_device_code(&self, device_code: &str) -> Result<Option<DeviceCode>, AuthError> {
        find(self, "deviceCode", device_code).await
    }

    async fn find_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, AuthError> {
        find(self, "userCode", user_code).await
    }

    async fn bind_pending_user(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<DeviceCode>, AuthError> {
        update(
            self,
            &[
                eq("id", id),
                eq("status", "pending"),
                SqliteFilter::equal("userId", Value::Null),
            ],
            Map::from_iter([("userId".into(), json!(user_id))]),
        )
        .await
    }

    async fn update_last_polled_at(
        &self,
        id: &str,
        polled_at: DateTime<Utc>,
    ) -> Result<Option<DeviceCode>, AuthError> {
        update(
            self,
            &[eq("id", id)],
            Map::from_iter([("lastPolledAt".into(), json!(polled_at))]),
        )
        .await
    }

    async fn update_device_code_status(
        &self,
        id: &str,
        status: DeviceCodeStatus,
    ) -> Result<Option<DeviceCode>, AuthError> {
        update(
            self,
            &[eq("id", id)],
            Map::from_iter([("status".into(), json!(status))]),
        )
        .await
    }

    async fn delete_device_code(&self, id: &str) -> Result<Option<DeviceCode>, AuthError> {
        self.consume_record("deviceCode", &[eq("id", id)])
            .await?
            .map(|record| codec::decode("deviceCode", record))
            .transpose()
    }

    async fn consume_approved_device_code(
        &self,
        id: &str,
        owner: DeviceCodeOwner,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let (field, value) = match owner {
            DeviceCodeOwner::ClientId(value) => ("clientId", value),
            DeviceCodeOwner::OAuthClientId(_)
                if !self
                    .physical_schema()?
                    .model("deviceCode")?
                    .has_field("oauthClientId") =>
            {
                return Ok(None);
            }
            DeviceCodeOwner::OAuthClientId(value) => ("oauthClientId", value),
        };
        self.consume_record(
            "deviceCode",
            &[eq("id", id), eq("status", "approved"), eq(field, &value)],
        )
        .await?
        .map(|record| codec::decode("deviceCode", record))
        .transpose()
    }
}

async fn find(
    store: &SqliteStore,
    field: &str,
    value: &str,
) -> Result<Option<DeviceCode>, AuthError> {
    store
        .find_record("deviceCode", &[eq(field, value)], &[])
        .await?
        .map(|record| codec::decode("deviceCode", record))
        .transpose()
}
async fn update(
    store: &SqliteStore,
    filters: &[SqliteFilter],
    values: Map<String, Value>,
) -> Result<Option<DeviceCode>, AuthError> {
    store
        .update_record("deviceCode", filters, values)
        .await?
        .map(|record| codec::decode("deviceCode", record))
        .transpose()
}
fn eq(field: &str, value: &str) -> SqliteFilter {
    SqliteFilter::equal(field, json!(value))
}
