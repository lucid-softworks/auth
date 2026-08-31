mod predicate;
pub(in crate::mssql) mod execute;
mod join;

use serde_json::Value;
use std::ops::{Deref, DerefMut};

/// One Better Auth adapter predicate using a logical schema field.
#[derive(Debug, Clone, PartialEq)]
pub struct MssqlFilter {
    pub field: String,
    pub value: Value,
    pub operator: MssqlFilterOperator,
    pub connector: MssqlFilterConnector,
    pub mode: MssqlComparisonMode,
}

impl MssqlFilter {
    pub fn equal(field: impl Into<String>, value: Value) -> Self {
        Self {
            field: field.into(),
            value,
            operator: MssqlFilterOperator::Eq,
            connector: MssqlFilterConnector::And,
            mode: MssqlComparisonMode::Sensitive,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MssqlFilterOperator {
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
pub enum MssqlFilterConnector {
    #[default]
    And,
    Or,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MssqlComparisonMode {
    #[default]
    Sensitive,
    Insensitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MssqlSort {
    pub field: String,
    pub direction: MssqlSortDirection,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MssqlSortDirection {
    #[default]
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MssqlJoinRelation {
    OneToOne,
    #[default]
    OneToMany,
}

/// One Better Auth left join using logical model and field names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MssqlJoin {
    pub model: String,
    pub local_field: String,
    pub foreign_field: String,
    pub relation: MssqlJoinRelation,
    /// Per-relation result limit. Better Auth defaults to 100 when omitted.
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MssqlFindOptions {
    pub select: Vec<String>,
    pub sort: Option<MssqlSort>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub joins: Vec<MssqlJoin>,
}

/// One explicit SQL Server transaction pinned to a pooled Tiberius connection.
pub struct MssqlTransaction {
    store: super::MssqlStore,
    connection: Option<bb8::PooledConnection<'static, bb8_tiberius::ConnectionManager>>,
    transactional: bool,
}

impl super::MssqlStore {
    pub async fn begin(&self) -> Result<MssqlTransaction, crate::AuthError> {
        let mut connection = self.pool.clone().get_owned().await.map_err(storage)?;
        connection
            .simple_query("begin transaction")
            .await
            .map_err(storage)?
            .into_results()
            .await
            .map_err(storage)?;
        Ok(MssqlTransaction {
            store: self.clone(),
            connection: Some(connection),
            transactional: true,
        })
    }

    pub(super) async fn sequential_connection(&self) -> Result<MssqlTransaction, crate::AuthError> {
        let connection = self.pool.clone().get_owned().await.map_err(storage)?;
        Ok(MssqlTransaction {
            store: self.clone(),
            connection: Some(connection),
            transactional: false,
        })
    }
}

impl MssqlTransaction {
    pub async fn insert_record(
        &mut self,
        model: &str,
        record: serde_json::Map<String, Value>,
    ) -> Result<Option<serde_json::Map<String, Value>>, crate::AuthError> {
        let store = self.store.clone();
        let schema = store.physical_schema()?;
        execute::insert(&mut *self, schema, model, record).await
    }

    pub async fn find_record(
        &mut self,
        model: &str,
        filters: &[MssqlFilter],
        select: &[String],
    ) -> Result<Option<serde_json::Map<String, Value>>, crate::AuthError> {
        let store = self.store.clone();
        let schema = store.physical_schema()?;
        execute::find_one(&mut *self, schema, model, filters, select).await
    }

    pub async fn delete_records(
        &mut self,
        model: &str,
        filters: &[MssqlFilter],
    ) -> Result<u64, crate::AuthError> {
        let store = self.store.clone();
        let schema = store.physical_schema()?;
        execute::delete_many(&mut *self, schema, model, filters).await
    }

    pub async fn update_record(
        &mut self,
        model: &str,
        filters: &[MssqlFilter],
        values: serde_json::Map<String, Value>,
    ) -> Result<Option<serde_json::Map<String, Value>>, crate::AuthError> {
        let store = self.store.clone();
        let schema = store.physical_schema()?;
        execute::update_one(&mut *self, schema, model, filters, values).await
    }

    pub async fn consume_record(
        &mut self,
        model: &str,
        filters: &[MssqlFilter],
    ) -> Result<Option<serde_json::Map<String, Value>>, crate::AuthError> {
        let store = self.store.clone();
        let schema = store.physical_schema()?;
        execute::consume_one(&mut *self, schema, model, filters).await
    }

    pub async fn increment_record(
        &mut self,
        model: &str,
        filters: &[MssqlFilter],
        increments: serde_json::Map<String, Value>,
        set: serde_json::Map<String, Value>,
    ) -> Result<Option<serde_json::Map<String, Value>>, crate::AuthError> {
        let store = self.store.clone();
        let schema = store.physical_schema()?;
        execute::increment_one(&mut *self, schema, model, filters, increments, set).await
    }

    pub async fn commit(mut self) -> Result<(), crate::AuthError> {
        self.finish("commit transaction").await
    }

    pub async fn rollback(mut self) -> Result<(), crate::AuthError> {
        self.finish("rollback transaction").await
    }

    async fn finish(&mut self, sql: &str) -> Result<(), crate::AuthError> {
        let mut connection = self.connection.take().ok_or_else(closed)?;
        if !self.transactional {
            return Ok(());
        }
        connection
            .simple_query(sql)
            .await
            .map_err(storage)?
            .into_results()
            .await
            .map_err(storage)?;
        Ok(())
    }
}

impl Deref for MssqlTransaction {
    type Target = super::adapter::MssqlClient;

    fn deref(&self) -> &Self::Target {
        self.connection
            .as_deref()
            .expect("MSSQL transaction is active")
    }
}

impl DerefMut for MssqlTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection
            .as_deref_mut()
            .expect("MSSQL transaction is active")
    }
}

impl Drop for MssqlTransaction {
    fn drop(&mut self) {
        let Some(mut connection) = self.connection.take() else {
            return;
        };
        if !self.transactional {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            std::mem::forget(connection);
            return;
        };
        runtime.spawn(async move {
            if let Ok(stream) = connection.simple_query("rollback transaction").await {
                let _ = stream.into_results().await;
            }
        });
    }
}

fn closed() -> crate::AuthError {
    crate::AuthError::InvalidConfiguration("MSSQL transaction is already closed".into())
}

fn storage(error: impl std::fmt::Display) -> crate::AuthError {
    crate::AuthError::Storage(error.to_string())
}
