use super::{PostgresModel, PostgresStore, storage_error};
use crate::{
    AuthError, DatabaseCreateOperation, DatabaseModel, DatabaseRecord, DatabaseTransaction,
    DatabaseTransactionOperation,
};
use async_trait::async_trait;
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, Transaction};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex;

mod records;

pub(super) async fn run(
    store: &PostgresStore,
    operation: Box<dyn DatabaseTransactionOperation>,
) -> Result<Box<dyn std::any::Any + Send>, AuthError> {
    let sql = store.pool.begin().await.map_err(storage_error)?;
    let transaction = Arc::new(PostgresTransaction {
        store: store.clone(),
        sql: Mutex::new(Some(sql)),
        active: AtomicBool::new(true),
    });
    let result = crate::database_hooks::scope_transaction(
        transaction.clone(),
        operation.execute(transaction.clone()),
    )
    .await;
    transaction.active.store(false, Ordering::Release);
    let sql = transaction
        .sql
        .lock()
        .await
        .take()
        .ok_or_else(closed_transaction)?;
    match result {
        Ok(value) => {
            sql.commit().await.map_err(storage_error)?;
            Ok(value)
        }
        Err(error) => {
            sql.rollback().await.map_err(storage_error)?;
            Err(error)
        }
    }
}

struct PostgresTransaction {
    store: PostgresStore,
    sql: Mutex<Option<Transaction<'static, Postgres>>>,
    active: AtomicBool,
}

impl PostgresTransaction {
    fn ensure_active(&self) -> Result<(), AuthError> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(closed_transaction())
        }
    }

    fn model(&self, model: DatabaseModel) -> Result<PostgresModel<'_>, AuthError> {
        if model == DatabaseModel::Organization {
            return Err(AuthError::InvalidConfiguration(
                "organization transactions use the organization store boundary".into(),
            ));
        }
        self.store.physical_model(model.as_str())
    }
}

#[async_trait]
impl DatabaseTransaction for PostgresTransaction {
    async fn find_by_id(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError> {
        self.ensure_active()?;
        let model = self.model(model)?;
        let mut query = super::rows::select_query(&model);
        query.push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &model, "id", json!(id))?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        query
            .build()
            .fetch_optional(&mut **sql)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| decode_record(&model, row))
            .transpose()
    }

    async fn create(
        &self,
        operation: DatabaseCreateOperation,
    ) -> Result<DatabaseRecord, AuthError> {
        self.ensure_active()?;
        let model = self.model(operation.model())?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        match operation {
            DatabaseCreateOperation::User(value) => {
                let (record, id) = value.into_parts(&self.store)?;
                super::user::insert_transaction(sql, &model, record, &id)
                    .await
                    .map(DatabaseRecord::User)
            }
            DatabaseCreateOperation::Session(value) => {
                let (record, id) = value.into_parts(&self.store)?;
                let writes = super::session::session_writes(&model, &record, &id)?;
                insert_record(sql, &model, writes).await
            }
            DatabaseCreateOperation::Account(value) => {
                let (record, id) = value.into_parts(&self.store)?;
                super::oauth::insert_account_transaction(sql, &model, &record, &id)
                    .await
                    .map(DatabaseRecord::Account)
            }
            DatabaseCreateOperation::Verification(value) => {
                let (record, id) = value.into_parts(&self.store)?;
                let writes = super::verification::verification_writes(&model, &record, &id)?;
                insert_record(sql, &model, writes).await
            }
        }
    }

    async fn update(&self, record: DatabaseRecord) -> Result<DatabaseRecord, AuthError> {
        self.ensure_active()?;
        let model = self.model(record.model())?;
        let id = record_id(&record);
        let writes = update_writes(&model, &record)?;
        let mut query = super::rows::update_query(&model, writes);
        query.push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &model, "id", json!(id))?;
        query.push(" RETURNING ").push(model.all_projection());
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        let row = query
            .build()
            .fetch_optional(&mut **sql)
            .await
            .map_err(storage_error)?
            .ok_or(AuthError::NotFound)?;
        decode_record(&model, &row)
    }

    async fn delete(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError> {
        self.ensure_active()?;
        let model = self.model(model)?;
        let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
        query.push(model.quoted_table()).push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &model, "id", json!(id))?;
        query.push(" RETURNING ").push(model.all_projection());
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        query
            .build()
            .fetch_optional(&mut **sql)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| decode_record(&model, row))
            .transpose()
    }

    async fn find_records(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&crate::DashAdapterSort>,
        select: &[String],
    ) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, AuthError> {
        records::find(
            self,
            model,
            where_clause,
            limit,
            offset,
            sort,
            select,
        )
        .await
    }

    async fn create_record(
        &self,
        model: &str,
        data: serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, AuthError> {
        records::create(self, model, data).await
    }

    async fn update_record(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
        update: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        records::update(self, model, where_clause, update).await
    }

    async fn delete_records(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
    ) -> Result<u64, AuthError> {
        records::delete(self, model, where_clause).await
    }

    async fn count_records(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
    ) -> Result<u64, AuthError> {
        records::count(self, model, where_clause).await
    }

    async fn increment_record(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
        increments: serde_json::Map<String, serde_json::Value>,
        set: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        records::increment(self, model, where_clause, increments, set).await
    }
}

async fn insert_record(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    writes: Vec<super::PostgresWrite<'_>>,
) -> Result<DatabaseRecord, AuthError> {
    let mut query = super::rows::insert_query(model, writes);
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    decode_record(model, &row)
}

fn update_writes<'a>(
    model: &'a PostgresModel<'a>,
    record: &DatabaseRecord,
) -> Result<Vec<super::PostgresWrite<'a>>, AuthError> {
    let explicit = super::rows::explicit_id(record_id(record));
    let mut writes = match record {
        DatabaseRecord::User(record) => super::rows::user_writes(model, record, &explicit)?,
        DatabaseRecord::Session(record) => {
            super::session::session_writes(model, record, &explicit)?
        }
        DatabaseRecord::Account(record) => super::oauth::account_writes(model, record, &explicit)?,
        DatabaseRecord::Verification(record) => {
            super::verification::verification_writes(model, record, &explicit)?
        }
    };
    writes.retain(|write| !matches!(write.logical(), "id" | "createdAt"));
    Ok(writes)
}

fn decode_record(
    model: &PostgresModel<'_>,
    row: &sqlx::postgres::PgRow,
) -> Result<DatabaseRecord, AuthError> {
    match model.logical_name() {
        "user" => super::rows::decode_user(model, row).map(DatabaseRecord::User),
        "session" => super::session::decode_session(model, row).map(DatabaseRecord::Session),
        "account" => super::oauth::decode_account(model, row).map(DatabaseRecord::Account),
        "verification" => {
            super::verification::decode_verification(model, row).map(DatabaseRecord::Verification)
        }
        logical => Err(AuthError::InvalidConfiguration(format!(
            "unsupported transaction model '{logical}'"
        ))),
    }
}

fn record_id(record: &DatabaseRecord) -> String {
    match record {
        DatabaseRecord::User(record) => record.id.clone(),
        DatabaseRecord::Session(record) => record.id.clone(),
        DatabaseRecord::Account(record) => record.id.clone(),
        DatabaseRecord::Verification(record) => record.id.clone(),
    }
}

fn closed_transaction() -> AuthError {
    AuthError::Storage("database transaction is no longer active".into())
}
