use super::{
    PostgresDeviceAuthorizationStore,
    rows::{DeviceCodeRow, OAUTH_FIELDS, STANDALONE_FIELDS},
};
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
use uuid::Uuid;

fn convert(row: Option<DeviceCodeRow>) -> Result<Option<DeviceCode>, AuthError> {
    row.map(TryInto::try_into).transpose()
}

#[async_trait]
impl DeviceAuthorizationStore for PostgresDeviceAuthorizationStore {
    async fn create_device_code(
        &self,
        code: DeviceCode,
    ) -> Result<DeviceCodeCreateOutcome, AuthError> {
        let model = self.schema.model();
        let result = if self.oauth_mode {
            let fields = [STANDALONE_FIELDS, OAUTH_FIELDS].concat();
            sqlx::query_as::<_, DeviceCodeRow>(&format!(
                "INSERT INTO {} ({}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING {}",
                model.table(),
                model.columns(&fields),
                model.projection(&fields),
            ))
            .bind(code.id)
            .bind(&code.device_code)
            .bind(&code.user_code)
            .bind(code.user_id)
            .bind(code.expires_at)
            .bind(code.status.as_str())
            .bind(code.last_polled_at)
            .bind(code.polling_interval)
            .bind(&code.client_id)
            .bind(&code.scope)
            .bind(&code.resources)
            .bind(&code.oauth_client_id)
            .fetch_one(self.pool())
            .await
        } else {
            sqlx::query_as::<_, DeviceCodeRow>(&format!(
                "INSERT INTO {} ({}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING {}, NULL::TEXT[] AS \"resources\", NULL::TEXT AS \"oauth_client_id\"",
                model.table(),
                model.columns(STANDALONE_FIELDS),
                model.projection(STANDALONE_FIELDS),
            ))
            .bind(code.id)
            .bind(&code.device_code)
            .bind(&code.user_code)
            .bind(code.user_id)
            .bind(code.expires_at)
            .bind(code.status.as_str())
            .bind(code.last_polled_at)
            .bind(code.polling_interval)
            .bind(&code.client_id)
            .bind(&code.scope)
            .fetch_one(self.pool())
            .await
        };
        match result {
            Ok(row) => Ok(DeviceCodeCreateOutcome::Created(row.try_into()?)),
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
        find_by(self, "deviceCode", device_code).await
    }

    async fn find_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, AuthError> {
        find_by(self, "userCode", user_code).await
    }

    async fn bind_pending_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let model = self.schema.model();
        convert(
            sqlx::query_as::<_, DeviceCodeRow>(&format!(
                "UPDATE {} SET {}=$2 WHERE \"id\"=$1 AND {}='pending' AND {} IS NULL RETURNING {}",
                model.table(),
                model.column("userId"),
                model.column("status"),
                model.column("userId"),
                projection(self),
            ))
            .bind(id)
            .bind(user_id)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_error)?,
        )
    }

    async fn update_last_polled_at(
        &self,
        id: Uuid,
        last_polled_at: DateTime<Utc>,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let model = self.schema.model();
        convert(
            sqlx::query_as::<_, DeviceCodeRow>(&format!(
                "UPDATE {} SET {}=$2 WHERE \"id\"=$1 RETURNING {}",
                model.table(),
                model.column("lastPolledAt"),
                projection(self),
            ))
            .bind(id)
            .bind(last_polled_at)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_error)?,
        )
    }

    async fn update_device_code_status(
        &self,
        id: Uuid,
        status: DeviceCodeStatus,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let model = self.schema.model();
        convert(
            sqlx::query_as::<_, DeviceCodeRow>(&format!(
                "UPDATE {} SET {}=$2 WHERE \"id\"=$1 RETURNING {}",
                model.table(),
                model.column("status"),
                projection(self),
            ))
            .bind(id)
            .bind(status.as_str())
            .fetch_optional(self.pool())
            .await
            .map_err(storage_error)?,
        )
    }

    async fn delete_device_code(&self, id: Uuid) -> Result<Option<DeviceCode>, AuthError> {
        let model = self.schema.model();
        convert(
            sqlx::query_as::<_, DeviceCodeRow>(&format!(
                "DELETE FROM {} WHERE \"id\"=$1 RETURNING {}",
                model.table(),
                projection(self),
            ))
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_error)?,
        )
    }

    async fn consume_approved_device_code(
        &self,
        id: Uuid,
        owner: DeviceCodeOwner,
    ) -> Result<Option<DeviceCode>, AuthError> {
        let model = self.schema.model();
        let (owner_field, owner_value) = match owner {
            DeviceCodeOwner::ClientId(value) => ("clientId", value),
            DeviceCodeOwner::OAuthClientId(_) if !self.oauth_mode => return Ok(None),
            DeviceCodeOwner::OAuthClientId(value) => ("oauthClientId", value),
        };
        convert(
            sqlx::query_as::<_, DeviceCodeRow>(&format!(
                "DELETE FROM {} WHERE \"id\"=$1 AND {}=$2 AND {}='approved' RETURNING {}",
                model.table(),
                model.column(owner_field),
                model.column("status"),
                projection(self),
            ))
            .bind(id)
            .bind(owner_value)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_error)?,
        )
    }
}

async fn find_by(
    store: &PostgresDeviceAuthorizationStore,
    field: &str,
    value: &str,
) -> Result<Option<DeviceCode>, AuthError> {
    let model = store.schema.model();
    convert(
        sqlx::query_as::<_, DeviceCodeRow>(&format!(
            "SELECT {} FROM {} WHERE {}=$1",
            projection(store),
            model.table(),
            model.column(field),
        ))
        .bind(value)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

fn projection(store: &PostgresDeviceAuthorizationStore) -> String {
    let model = store.schema.model();
    let mut projection = model.projection(STANDALONE_FIELDS);
    if store.oauth_mode {
        projection.push_str(", ");
        projection.push_str(&model.projection(OAUTH_FIELDS));
    } else {
        projection.push_str(", NULL::TEXT[] AS \"resources\", NULL::TEXT AS \"oauth_client_id\"");
    }
    projection
}
