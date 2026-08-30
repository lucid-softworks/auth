use async_trait::async_trait;
use serde_json::{Map, Value};
use std::{fmt, sync::Arc};

/// One value accepted by Cloudflare D1 prepared-statement binding.
#[derive(Debug, Clone, PartialEq)]
pub enum D1Value {
    Null,
    Text(String),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Blob(Vec<u8>),
}

/// A compiled SQLite statement and its ordered bound values.
#[derive(Debug, Clone, PartialEq)]
pub struct D1Statement {
    pub sql: String,
    pub parameters: Vec<D1Value>,
}

impl D1Statement {
    pub fn new(sql: impl Into<String>, parameters: Vec<D1Value>) -> Self {
        Self {
            sql: sql.into(),
            parameters,
        }
    }
}

/// Observable output of D1's prepared-statement `all()` operation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct D1QueryResult {
    pub results: Vec<Map<String, Value>>,
    pub changes: Option<u64>,
    pub last_row_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D1TransportError(String);

impl D1TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for D1TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for D1TransportError {}

/// Minimal capability boundary implemented by a Cloudflare D1 binding.
///
/// Implementations must execute `all` as `prepare(sql).bind(...).all()`.
/// `batch_all` is used only for a finite schema-introspection statement set.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait D1Database: Send + Sync {
    async fn all(&self, statement: D1Statement) -> Result<D1QueryResult, D1TransportError>;

    async fn batch_all(
        &self,
        statements: Vec<D1Statement>,
    ) -> Result<Vec<D1QueryResult>, D1TransportError>;
}

pub(crate) type SharedD1Database = Arc<dyn D1Database>;

#[cfg(target_arch = "wasm32")]
pub struct WorkersD1Database(worker::D1Database);

#[cfg(target_arch = "wasm32")]
impl WorkersD1Database {
    pub fn new(database: worker::D1Database) -> Self {
        Self(database)
    }

    pub fn binding(&self) -> &worker::D1Database {
        &self.0
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl D1Database for WorkersD1Database {
    async fn all(&self, statement: D1Statement) -> Result<D1QueryResult, D1TransportError> {
        let prepared = prepare(&self.0, statement)?;
        prepared
            .all()
            .await
            .map_err(worker_error)
            .and_then(convert_result)
    }

    async fn batch_all(
        &self,
        statements: Vec<D1Statement>,
    ) -> Result<Vec<D1QueryResult>, D1TransportError> {
        let statements = statements
            .into_iter()
            .map(|statement| prepare(&self.0, statement))
            .collect::<Result<Vec<_>, _>>()?;
        self.0
            .batch(statements)
            .await
            .map_err(worker_error)?
            .into_iter()
            .map(convert_result)
            .collect()
    }
}

#[cfg(target_arch = "wasm32")]
fn prepare(
    database: &worker::D1Database,
    statement: D1Statement,
) -> Result<worker::D1PreparedStatement, D1TransportError> {
    let values = statement
        .parameters
        .iter()
        .map(worker_value)
        .collect::<Vec<_>>();
    database
        .prepare(statement.sql)
        .bind_refs(&values)
        .map_err(worker_error)
}

#[cfg(target_arch = "wasm32")]
fn worker_value(value: &D1Value) -> worker::D1Type<'_> {
    match value {
        D1Value::Null => worker::D1Type::Null,
        D1Value::Text(value) => worker::D1Type::Text(value),
        D1Value::Integer(value) => i32::try_from(*value).map_or_else(
            |_| worker::D1Type::Real(*value as f64),
            worker::D1Type::Integer,
        ),
        D1Value::Real(value) => worker::D1Type::Real(*value),
        D1Value::Boolean(value) => worker::D1Type::Boolean(*value),
        D1Value::Blob(value) => worker::D1Type::Blob(value),
    }
}

#[cfg(target_arch = "wasm32")]
fn convert_result(result: worker::D1Result) -> Result<D1QueryResult, D1TransportError> {
    if !result.success() {
        return Err(D1TransportError::new(
            result.error().unwrap_or_else(|| "D1 query failed".into()),
        ));
    }
    let rows = result
        .results::<Map<String, Value>>()
        .map_err(worker_error)?;
    let meta = result.meta().map_err(worker_error)?;
    Ok(D1QueryResult {
        results: rows,
        changes: meta
            .as_ref()
            .and_then(|meta| meta.changes)
            .map(|value| value as u64),
        last_row_id: meta.and_then(|meta| meta.last_row_id),
    })
}

#[cfg(target_arch = "wasm32")]
fn worker_error(error: worker::Error) -> D1TransportError {
    D1TransportError::new(error.to_string())
}
