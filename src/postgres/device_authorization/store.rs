use super::{PostgresDeviceAuthorizationStore, codec, query};
use crate::{
    AuthError,
    device_authorization::{
        DeviceAuthorizationStore, DeviceCode, DeviceCodeCreateOutcome, DeviceCodeOwner,
        DeviceCodeStatus,
    },
    postgres::storage_error,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::postgres::PgRow;
use uuid::Uuid;

#[async_trait]
impl DeviceAuthorizationStore for PostgresDeviceAuthorizationStore {
    async fn create_device_code(
        &self,
        code: DeviceCode,
    ) -> Result<DeviceCodeCreateOutcome, AuthError> {
        let model = self.model()?;
        let result = query::insert(&model, &code)?
            .build()
            .fetch_one(self.pool())
            .await;
        match result {
            Ok(row) => Ok(DeviceCodeCreateOutcome::Created(codec::decode(
                &model, &row,
            )?)),
            Err(error)
                if error
                    .as_database_error()
                    .is_some_and(|database| database.is_unique_violation()) =>
            {
                Ok(DeviceCodeCreateOutcome::UniqueConflict)
            }
            Err(error) => Err(storage_error(error)),
        }
    }

    async fn find_device_code(&self, device_code: &str) -> Result<Option<DeviceCode>, AuthError> {
        find_by(self, "deviceCode", Value::String(device_code.into())).await
    }

    async fn find_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, AuthError> {
        find_by(self, "userCode", Value::String(user_code.into())).await
    }

    async fn bind_pending_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let model = self.model()?;
        fetch_optional(
            &model,
            query::bind_pending_user(&model, id, user_id)?,
            self.pool(),
        )
        .await
    }

    async fn update_last_polled_at(
        &self,
        id: Uuid,
        last_polled_at: DateTime<Utc>,
    ) -> Result<Option<DeviceCode>, AuthError> {
        update(self, id, "lastPolledAt", json!(last_polled_at.to_rfc3339())).await
    }

    async fn update_device_code_status(
        &self,
        id: Uuid,
        status: DeviceCodeStatus,
    ) -> Result<Option<DeviceCode>, AuthError> {
        update(self, id, "status", json!(status.as_str())).await
    }

    async fn delete_device_code(&self, id: Uuid) -> Result<Option<DeviceCode>, AuthError> {
        let model = self.model()?;
        fetch_optional(&model, query::delete(&model, id), self.pool()).await
    }

    async fn consume_approved_device_code(
        &self,
        id: Uuid,
        owner: DeviceCodeOwner,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let model = self.model()?;
        let (owner_field, owner_value) = match owner {
            DeviceCodeOwner::ClientId(value) => ("clientId", value),
            DeviceCodeOwner::OAuthClientId(_) if !model.has_field("oauthClientId") => {
                return Ok(None);
            }
            DeviceCodeOwner::OAuthClientId(value) => ("oauthClientId", value),
        };
        fetch_optional(
            &model,
            query::consume(&model, id, owner_field, owner_value)?,
            self.pool(),
        )
        .await
    }
}

async fn find_by(
    store: &PostgresDeviceAuthorizationStore,
    field: &str,
    value: Value,
) -> Result<Option<DeviceCode>, AuthError> {
    let model = store.model()?;
    fetch_optional(&model, query::find_by(&model, field, value)?, store.pool()).await
}

async fn update(
    store: &PostgresDeviceAuthorizationStore,
    id: Uuid,
    field: &str,
    value: Value,
) -> Result<Option<DeviceCode>, AuthError> {
    let model = store.model()?;
    fetch_optional(
        &model,
        query::update_field(&model, id, field, value)?,
        store.pool(),
    )
    .await
}

async fn fetch_optional(
    model: &super::super::PostgresModel<'_>,
    mut query: sqlx::QueryBuilder<'static, sqlx::Postgres>,
    pool: &sqlx::PgPool,
) -> Result<Option<DeviceCode>, AuthError> {
    query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row: &PgRow| codec::decode(model, row))
        .transpose()
}
