use super::{
    SqliteFilter, SqliteFindOptions, SqliteSort, SqliteSortDirection, SqliteStore, codec,
    query::execute,
};
use crate::{
    AuthError, DashAdapterSort, DashAdapterWhere, DashSortDirection, DatabaseCreateOperation,
    DatabaseModel, DatabaseRecord, DatabaseTransaction, DatabaseTransactionOperation,
};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sqlx::{Sqlite, Transaction};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex;

pub(super) async fn run(
    store: &SqliteStore,
    operation: Box<dyn DatabaseTransactionOperation>,
) -> Result<Box<dyn std::any::Any + Send>, AuthError> {
    let sql = store.pool.begin().await.map_err(storage)?;
    let transaction = Arc::new(SqliteHookTransaction {
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
            sql.commit().await.map_err(storage)?;
            Ok(value)
        }
        Err(error) => {
            sql.rollback().await.map_err(storage)?;
            Err(error)
        }
    }
}

struct SqliteHookTransaction {
    store: SqliteStore,
    sql: Mutex<Option<Transaction<'static, Sqlite>>>,
    active: AtomicBool,
}

impl SqliteHookTransaction {
    fn ensure_active(&self) -> Result<(), AuthError> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(closed_transaction())
        }
    }

    fn model_name(model: DatabaseModel) -> Result<&'static str, AuthError> {
        match model {
            DatabaseModel::User => Ok("user"),
            DatabaseModel::Session => Ok("session"),
            DatabaseModel::Account => Ok("account"),
            DatabaseModel::Verification => Ok("verification"),
            DatabaseModel::Organization => Err(AuthError::InvalidConfiguration(
                "organization transactions use the organization store boundary".into(),
            )),
        }
    }
}

#[async_trait]
impl DatabaseTransaction for SqliteHookTransaction {
    async fn find_by_id(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError> {
        self.ensure_active()?;
        let model_name = Self::model_name(model)?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        execute::find_one(
            sql,
            schema,
            model_name,
            &[SqliteFilter::equal("id", json!(id))],
            &[],
        )
        .await?
        .map(|record| decode_record(model, record))
        .transpose()
    }

    async fn create(
        &self,
        operation: DatabaseCreateOperation,
    ) -> Result<DatabaseRecord, AuthError> {
        self.ensure_active()?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        let (model, record) = match operation {
            DatabaseCreateOperation::User(value) => {
                let (mut value, id) = value.into_parts(&self.store)?;
                value.email = value.email.to_lowercase();
                (
                    DatabaseModel::User,
                    codec::create_record(&self.store, "user", &value, &id)?,
                )
            }
            DatabaseCreateOperation::Session(value) => {
                let (value, id) = value.into_parts(&self.store)?;
                (
                    DatabaseModel::Session,
                    codec::create_record(&self.store, "session", &value, &id)?,
                )
            }
            DatabaseCreateOperation::Account(value) => {
                let (value, id) = value.into_parts(&self.store)?;
                (
                    DatabaseModel::Account,
                    codec::oauth_create_record(&self.store, &value, &id)?,
                )
            }
            DatabaseCreateOperation::Verification(value) => {
                let (value, id) = value.into_parts(&self.store)?;
                (
                    DatabaseModel::Verification,
                    codec::create_record(&self.store, "verification", &value, &id)?,
                )
            }
        };
        let model_name = Self::model_name(model)?;
        let record = execute::insert(sql, schema, model_name, record).await?;
        decode_record(model, record)
    }

    async fn update(&self, mut record: DatabaseRecord) -> Result<DatabaseRecord, AuthError> {
        self.ensure_active()?;
        if let DatabaseRecord::User(user) = &mut record {
            user.email = user.email.to_lowercase();
        }
        let model = record.model();
        let model_name = Self::model_name(model)?;
        let id = record_id(&record);
        let values = encode_update(&self.store, &record)?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        let stored = execute::update_one(
            sql,
            schema,
            model_name,
            &[SqliteFilter::equal("id", json!(id))],
            values,
        )
        .await?
        .ok_or(AuthError::NotFound)?;
        decode_record(model, stored)
    }

    async fn delete(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError> {
        self.ensure_active()?;
        let model_name = Self::model_name(model)?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        execute::consume_one(
            sql,
            schema,
            model_name,
            &[SqliteFilter::equal("id", json!(id))],
        )
        .await?
        .map(|record| decode_record(model, record))
            .transpose()
    }

    async fn find_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&DashAdapterSort>,
        select: &[String],
    ) -> Result<Vec<Map<String, Value>>, AuthError> {
        self.ensure_active()?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        execute::find_many(
            sql,
            schema,
            model,
            &super::dash::filters(where_clause),
            &SqliteFindOptions {
                select: select.to_vec(),
                sort: sort.map(|sort| SqliteSort {
                    field: sort.field.clone(),
                    direction: match sort.direction {
                        DashSortDirection::Asc => SqliteSortDirection::Ascending,
                        DashSortDirection::Desc => SqliteSortDirection::Descending,
                    },
                }),
                limit: limit.map(|limit| limit as u64),
                offset: Some(offset as u64),
            },
        )
        .await
    }

    async fn create_record(
        &self,
        model: &str,
        data: Map<String, Value>,
    ) -> Result<Map<String, Value>, AuthError> {
        self.ensure_active()?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        execute::insert(sql, schema, model, data).await
    }

    async fn update_record(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        update: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        self.ensure_active()?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        execute::update_one(
            sql,
            schema,
            model,
            &super::dash::filters(where_clause),
            update,
        )
        .await
    }

    async fn delete_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
    ) -> Result<u64, AuthError> {
        self.ensure_active()?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        execute::delete_many(
            sql,
            schema,
            model,
            &super::dash::filters(where_clause),
        )
        .await
    }

    async fn count_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
    ) -> Result<u64, AuthError> {
        self.ensure_active()?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        execute::count(
            sql,
            schema,
            model,
            &super::dash::filters(where_clause),
        )
        .await
    }

    async fn increment_record(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        self.ensure_active()?;
        let schema = self.store.physical_schema()?;
        let mut sql = self.sql.lock().await;
        let sql = sql.as_mut().ok_or_else(closed_transaction)?;
        execute::increment_one(
            sql,
            schema,
            model,
            &super::dash::filters(where_clause),
            increments,
            set,
        )
        .await
    }
}

fn encode_update(
    store: &SqliteStore,
    record: &DatabaseRecord,
) -> Result<Map<String, Value>, AuthError> {
    match record {
        DatabaseRecord::User(value) => codec::update_record(store, "user", value),
        DatabaseRecord::Session(value) => codec::update_record(store, "session", value),
        DatabaseRecord::Account(value) => codec::oauth_update_record(store, value),
        DatabaseRecord::Verification(value) => codec::update_record(store, "verification", value),
    }
}

fn decode_record(
    model: DatabaseModel,
    record: Map<String, Value>,
) -> Result<DatabaseRecord, AuthError> {
    match model {
        DatabaseModel::User => codec::decode("user", record).map(DatabaseRecord::User),
        DatabaseModel::Session => codec::decode("session", record).map(DatabaseRecord::Session),
        DatabaseModel::Account => codec::decode_oauth(record).map(DatabaseRecord::Account),
        DatabaseModel::Verification => {
            codec::decode("verification", record).map(DatabaseRecord::Verification)
        }
        DatabaseModel::Organization => Err(AuthError::InvalidConfiguration(
            "organization transactions use the organization store boundary".into(),
        )),
    }
}

fn record_id(record: &DatabaseRecord) -> &str {
    match record {
        DatabaseRecord::User(value) => &value.id,
        DatabaseRecord::Session(value) => &value.id,
        DatabaseRecord::Account(value) => &value.id,
        DatabaseRecord::Verification(value) => &value.id,
    }
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}

fn closed_transaction() -> AuthError {
    AuthError::Storage("database transaction is no longer active".into())
}
