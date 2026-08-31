use super::{
    MySqlFilter, MySqlFindOptions, MySqlSort, MySqlSortDirection, MySqlStore, codec,
    query::execute,
};
use crate::{AuthError, VerificationStore, VerificationValue, store::DatabaseCreate};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;

#[async_trait]
impl VerificationStore for MySqlStore {
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
        let (value, id) = value.into_parts(self)?;
        let record = codec::create_record(self, "verification", &value, &id)?;
        codec::decode(
            "verification",
            self.insert_required_record("verification", record).await?,
        )
    }

    async fn reserve_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        match self.create_verification(value).await {
            Ok(value) => Ok(Some(value)),
            Err(error) if crate::mysql::error::is_unique_violation(&error) => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        latest(self, identifier).await
    }

    async fn consume_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let filters = [eq("identifier", identifier)];
        let consumed = execute::consume_latest(
            &mut transaction,
            schema,
            "verification",
            &filters,
            "createdAt",
        )
        .await?
        .map(|record| codec::decode("verification", record))
        .transpose()?;
        if consumed.is_some() {
            execute::delete_many(&mut transaction, schema, "verification", &filters).await?;
        }
        transaction.commit().await.map_err(storage)?;
        Ok(consumed)
    }

    async fn update_verification(
        &self,
        value: VerificationValue,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let id = value.id.clone();
        let values = codec::update_record(self, "verification", &value)?;
        self.update_record("verification", &[eq("id", id)], values)
            .await?
            .map(|record| codec::decode("verification", record))
            .transpose()
    }

    async fn delete_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let filters = [eq("identifier", identifier)];
        let records = execute::find_many(
            &mut transaction,
            schema,
            "verification",
            &filters,
            &latest_options(),
        )
        .await?;
        execute::delete_many(&mut transaction, schema, "verification", &filters).await?;
        transaction.commit().await.map_err(storage)?;
        records
            .into_iter()
            .next()
            .map(|record| codec::decode("verification", record))
            .transpose()
    }

    async fn delete_expired_verifications(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        self.delete_records("verification", &[less_than("expiresAt", json!(now))])
            .await
    }
}

async fn latest(
    store: &MySqlStore,
    identifier: &str,
) -> Result<Option<VerificationValue>, AuthError> {
    store
        .find_records(
            "verification",
            &[eq("identifier", identifier)],
            &latest_options(),
        )
        .await?
        .into_iter()
        .next()
        .map(|record| codec::decode("verification", record))
        .transpose()
}

fn latest_options() -> MySqlFindOptions {
    MySqlFindOptions {
        sort: Some(MySqlSort {
            field: "createdAt".into(),
            direction: MySqlSortDirection::Descending,
        }),
        limit: Some(1),
        ..MySqlFindOptions::default()
    }
}

fn eq(field: &str, value: impl serde::Serialize) -> MySqlFilter {
    MySqlFilter::equal(field, json!(value))
}

fn less_than(field: &str, value: serde_json::Value) -> MySqlFilter {
    MySqlFilter {
        field: field.into(),
        value,
        operator: super::MySqlFilterOperator::Lt,
        connector: super::MySqlFilterConnector::And,
        mode: super::MySqlComparisonMode::Sensitive,
    }
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
