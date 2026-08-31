use crate::{AuthError, mysql::MySqlStore};
use serde_json::{Map, Value};
use sqlx::{MySql, Transaction};

pub(in crate::mysql) mod execute;
mod predicate;

/// One Better Auth adapter predicate using a logical schema field.
#[derive(Debug, Clone, PartialEq)]
pub struct MySqlFilter {
    pub field: String,
    pub value: Value,
    pub operator: MySqlFilterOperator,
    pub connector: MySqlFilterConnector,
    pub mode: MySqlComparisonMode,
}

impl MySqlFilter {
    pub fn equal(field: impl Into<String>, value: Value) -> Self {
        Self {
            field: field.into(),
            value,
            operator: MySqlFilterOperator::Eq,
            connector: MySqlFilterConnector::And,
            mode: MySqlComparisonMode::Sensitive,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MySqlFilterOperator {
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
pub enum MySqlFilterConnector {
    #[default]
    And,
    Or,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MySqlComparisonMode {
    #[default]
    Sensitive,
    Insensitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MySqlSort {
    pub field: String,
    pub direction: MySqlSortDirection,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MySqlSortDirection {
    #[default]
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MySqlFindOptions {
    pub select: Vec<String>,
    pub sort: Option<MySqlSort>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

/// Explicit real MySQL transaction. Dropping it rolls back through SQLx.
pub struct MySqlTransaction<'a> {
    transaction: Transaction<'a, MySql>,
    schema: &'a super::schema::MySqlSchema,
}

impl MySqlStore {
    pub async fn begin(&self) -> Result<MySqlTransaction<'_>, AuthError> {
        let schema = self.physical_schema()?;
        let transaction = self.pool.begin().await.map_err(storage)?;
        Ok(MySqlTransaction {
            transaction,
            schema,
        })
    }

    pub async fn insert_record(
        &self,
        model: &str,
        record: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::insert(&mut connection, schema, model, record).await
    }

    pub async fn find_record(
        &self,
        model: &str,
        filters: &[MySqlFilter],
        select: &[String],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::find_one(&mut connection, schema, model, filters, select).await
    }

    pub async fn find_records(
        &self,
        model: &str,
        filters: &[MySqlFilter],
        options: &MySqlFindOptions,
    ) -> Result<Vec<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::find_many(&mut connection, schema, model, filters, options).await
    }

    pub async fn update_record(
        &self,
        model: &str,
        filters: &[MySqlFilter],
        values: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::update_one(&mut connection, schema, model, filters, values).await
    }

    pub async fn update_records(
        &self,
        model: &str,
        filters: &[MySqlFilter],
        values: Map<String, Value>,
    ) -> Result<u64, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::update_many(&mut connection, schema, model, filters, values).await
    }

    pub async fn count_records(
        &self,
        model: &str,
        filters: &[MySqlFilter],
    ) -> Result<u64, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::count(&mut connection, schema, model, filters).await
    }

    pub async fn delete_records(
        &self,
        model: &str,
        filters: &[MySqlFilter],
    ) -> Result<u64, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::delete_many(&mut connection, schema, model, filters).await
    }

    pub async fn consume_record(
        &self,
        model: &str,
        filters: &[MySqlFilter],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::consume_one(&mut connection, schema, model, filters).await
    }

    pub async fn increment_record(
        &self,
        model: &str,
        filters: &[MySqlFilter],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        let schema = self.physical_schema()?;
        let mut connection = self.pool.acquire().await.map_err(storage)?;
        execute::increment_one(&mut connection, schema, model, filters, increments, set).await
    }
}

impl MySqlTransaction<'_> {
    pub async fn insert_record(
        &mut self,
        model: &str,
        record: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::insert(&mut self.transaction, self.schema, model, record).await
    }

    pub async fn find_record(
        &mut self,
        model: &str,
        filters: &[MySqlFilter],
        select: &[String],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::find_one(&mut self.transaction, self.schema, model, filters, select).await
    }

    pub async fn delete_records(
        &mut self,
        model: &str,
        filters: &[MySqlFilter],
    ) -> Result<u64, AuthError> {
        execute::delete_many(&mut self.transaction, self.schema, model, filters).await
    }

    pub async fn update_record(
        &mut self,
        model: &str,
        filters: &[MySqlFilter],
        values: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::update_one(&mut self.transaction, self.schema, model, filters, values).await
    }

    pub async fn consume_record(
        &mut self,
        model: &str,
        filters: &[MySqlFilter],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::consume_one_in_transaction(&mut self.transaction, self.schema, model, filters)
            .await
    }

    pub async fn increment_record(
        &mut self,
        model: &str,
        filters: &[MySqlFilter],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::increment_one_in_transaction(
            &mut self.transaction,
            self.schema,
            model,
            filters,
            increments,
            set,
        )
        .await
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
