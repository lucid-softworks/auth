use crate::{AuthError, sqlite::SqliteStore};
use serde_json::{Map, Value};
use sqlx::{Sqlite, Transaction};

pub(in crate::sqlite) mod execute;
mod predicate;

/// One Better Auth adapter predicate using a logical schema field.
#[derive(Debug, Clone, PartialEq)]
pub struct SqliteFilter {
    pub field: String,
    pub value: Value,
    pub operator: SqliteFilterOperator,
    pub connector: SqliteFilterConnector,
    pub mode: SqliteComparisonMode,
}

impl SqliteFilter {
    pub fn equal(field: impl Into<String>, value: Value) -> Self {
        Self {
            field: field.into(),
            value,
            operator: SqliteFilterOperator::Eq,
            connector: SqliteFilterConnector::And,
            mode: SqliteComparisonMode::Sensitive,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SqliteFilterOperator {
    #[default]
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SqliteFilterConnector {
    #[default]
    And,
    Or,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SqliteComparisonMode {
    #[default]
    Sensitive,
    Insensitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteSort {
    pub field: String,
    pub direction: SqliteSortDirection,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SqliteSortDirection {
    #[default]
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SqliteFindOptions {
    pub select: Vec<String>,
    pub sort: Option<SqliteSort>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

/// Explicit real SQLite transaction. Dropping it rolls back through SQLx.
pub struct SqliteTransaction<'a> {
    transaction: Transaction<'a, Sqlite>,
    schema: &'a super::schema::SqliteSchema,
}

impl SqliteStore {
    pub async fn begin(&self) -> Result<SqliteTransaction<'_>, AuthError> {
        let schema = self.physical_schema()?;
        let transaction = self.pool.begin().await.map_err(storage)?;
        Ok(SqliteTransaction {
            transaction,
            schema,
        })
    }

    pub async fn insert_record(
        &self,
        model: &str,
        record: Map<String, Value>,
    ) -> Result<Map<String, Value>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::insert(&mut connection, schema, model, record).await
    }

    pub async fn find_record(
        &self,
        model: &str,
        filters: &[SqliteFilter],
        select: &[String],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::find_one(&mut connection, schema, model, filters, select).await
    }

    pub async fn find_records(
        &self,
        model: &str,
        filters: &[SqliteFilter],
        options: &SqliteFindOptions,
    ) -> Result<Vec<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::find_many(&mut connection, schema, model, filters, options).await
    }

    pub async fn update_record(
        &self,
        model: &str,
        filters: &[SqliteFilter],
        values: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::update_one(&mut connection, schema, model, filters, values).await
    }

    pub async fn update_records(
        &self,
        model: &str,
        filters: &[SqliteFilter],
        values: Map<String, Value>,
    ) -> Result<u64, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::update_many(&mut connection, schema, model, filters, values).await
    }

    pub async fn count_records(
        &self,
        model: &str,
        filters: &[SqliteFilter],
    ) -> Result<u64, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::count(&mut connection, schema, model, filters).await
    }

    pub async fn delete_records(
        &self,
        model: &str,
        filters: &[SqliteFilter],
    ) -> Result<u64, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::delete_many(&mut connection, schema, model, filters).await
    }

    pub async fn consume_record(
        &self,
        model: &str,
        filters: &[SqliteFilter],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::consume_one(&mut connection, schema, model, filters).await
    }

    pub async fn increment_record(
        &self,
        model: &str,
        filters: &[SqliteFilter],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::increment_one(&mut connection, schema, model, filters, increments, set).await
    }
}

impl SqliteTransaction<'_> {
    pub async fn insert_record(
        &mut self,
        model: &str,
        record: Map<String, Value>,
    ) -> Result<Map<String, Value>, AuthError> {
        execute::insert(&mut self.transaction, self.schema, model, record).await
    }

    pub async fn find_record(
        &mut self,
        model: &str,
        filters: &[SqliteFilter],
        select: &[String],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::find_one(&mut self.transaction, self.schema, model, filters, select).await
    }

    pub async fn delete_records(
        &mut self,
        model: &str,
        filters: &[SqliteFilter],
    ) -> Result<u64, AuthError> {
        execute::delete_many(&mut self.transaction, self.schema, model, filters).await
    }

    pub async fn commit(self) -> Result<(), AuthError> {
        self.transaction.commit().await.map_err(storage)
    }

    pub async fn rollback(self) -> Result<(), AuthError> {
        self.transaction.rollback().await.map_err(storage)
    }
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
