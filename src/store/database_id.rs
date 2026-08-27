use super::AuthStore;
use crate::AuthError;
use async_trait::async_trait;

/// ID state passed from Better Auth's adapter transform into a create call.
///
/// Persisted records always expose a string ID. `Deferred` exists only at the
/// create boundary so adapters with native generation can omit the column and
/// return the generated value from the inserted row.
#[derive(Debug, Clone, PartialEq)]
pub enum PreparedDatabaseId {
    Value(DatabaseIdValue),
    /// Omit the ID and require the adapter/database to return it.
    Deferred,
    /// Omit a serial ID. In-memory plugin stores use this marker to produce
    /// the same decimal-string identity that a numeric database would return.
    DeferredSerial,
}

/// JavaScript value classes accepted by a forced Better Auth create ID.
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseIdInput {
    Absent,
    Null,
    Boolean(bool),
    Number(f64),
    String(String),
    /// A JavaScript array supplied by a database create hook.
    Array(Vec<serde_json::Value>),
}

/// Truthy ID value emitted by Better Auth's input transform.
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseIdValue {
    Boolean(bool),
    Number(f64),
    String(String),
    Array(Vec<serde_json::Value>),
}

impl DatabaseIdValue {
    pub fn into_output_string(self) -> String {
        match self {
            Self::Boolean(value) => value.to_string(),
            Self::Number(value) => javascript_number_string(value),
            Self::String(value) => value,
            Self::Array(value) => javascript_array_string(&value),
        }
    }

    pub fn to_json(&self) -> Result<serde_json::Value, AuthError> {
        match self {
            Self::Boolean(value) => Ok(serde_json::Value::Bool(*value)),
            Self::Number(value) => serde_json::Number::from_f64(*value)
                .map(serde_json::Value::Number)
                .ok_or_else(|| AuthError::Storage("database id is not a finite number".into())),
            Self::String(value) => Ok(serde_json::Value::String(value.clone())),
            Self::Array(value) => Ok(serde_json::Value::Array(value.clone())),
        }
    }
}

fn javascript_array_string(value: &[serde_json::Value]) -> String {
    value
        .iter()
        .map(javascript_array_element_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn javascript_array_element_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value
            .as_f64()
            .map(javascript_number_string)
            .unwrap_or_else(|| value.to_string()),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(value) => javascript_array_string(value),
        serde_json::Value::Object(_) => "[object Object]".into(),
    }
}

fn javascript_number_string(value: f64) -> String {
    ryu_js::Buffer::new().format(value).to_owned()
}

/// A lazy Better Auth ID transform evaluated at the actual insert branch.
#[derive(Clone)]
pub struct DatabaseIdPlan {
    strategy: crate::DatabaseIdGeneration,
    model: String,
    input: DatabaseIdInput,
    force_allow_id: bool,
}

impl std::fmt::Debug for DatabaseIdPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseIdPlan")
            .field("strategy", &self.strategy.kind())
            .field("model", &self.model)
            .field("input", &self.input)
            .field("force_allow_id", &self.force_allow_id)
            .finish()
    }
}

impl DatabaseIdPlan {
    /// Builds the lazy ID transform supplied to a public [`AuthStore`] create
    /// operation.
    pub fn new(
        strategy: crate::DatabaseIdGeneration,
        model: impl Into<String>,
        input: DatabaseIdInput,
        force_allow_id: bool,
    ) -> Self {
        Self {
            strategy,
            model: model.into(),
            input,
            force_allow_id,
        }
    }

    pub fn prepare(&self, store: &dyn AuthStore) -> Result<PreparedDatabaseId, AuthError> {
        self.strategy.prepare(
            store.database_adapter_name(),
            &self.model,
            store.database_id_capabilities(),
            store.database_id_generator(),
            self.force_allow_id,
            self.input.clone(),
        )
    }
}

/// One record after create hooks and Better Auth's ID transform have run.
#[derive(Debug, Clone)]
pub struct DatabaseCreate<T> {
    pub record: T,
    pub id: DatabaseIdPlan,
}

impl<T> DatabaseCreate<T> {
    /// Pairs an idless, hook-processed record with its lazy ID transform.
    pub fn new(record: T, id: DatabaseIdPlan) -> Self {
        Self { record, id }
    }

    pub fn into_parts(self, store: &dyn AuthStore) -> Result<(T, PreparedDatabaseId), AuthError> {
        let id = self.id.prepare(store)?;
        Ok((self.record, id))
    }
}

/// Explicit create/update state for Better Auth upserts.
#[derive(Debug, Clone)]
pub enum DatabaseWrite<T> {
    Create(DatabaseCreate<T>),
    Update(T),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseWriteOperation {
    Create,
    Update,
}

pub struct DependentAccountContext<'a> {
    pub user: &'a crate::AuthUser,
    pub user_operation: DatabaseWriteOperation,
    pub existing_account: Option<&'a crate::OAuthAccount>,
}

#[derive(Debug, Clone)]
pub struct DatabaseAccountOwnerWrite {
    pub owner: crate::OAuthAccountOwner,
    pub user_operation: DatabaseWriteOperation,
    pub account_operation: DatabaseWriteOperation,
}

/// Prepares an account only after its newly inserted user has a database ID.
///
/// SIWE still uses this narrower create-only contract; credential and OAuth
/// upserts use [`DependentAccountPreparer`] because they may update an
/// existing account.
#[async_trait]
pub trait DatabaseAccountCreate: Send + Sync {
    async fn prepare(
        &self,
        user: &crate::AuthUser,
    ) -> Result<DatabaseCreate<crate::OAuthAccount>, AuthError>;
}

/// Prepares an account after the store resolves the persisted user and account branch.
#[async_trait]
pub trait DependentAccountPreparer: Send + Sync {
    /// Returns the account identity that should be reserved while preparation runs.
    ///
    /// Stores that support concurrent in-process writes use this to reject a
    /// conflicting insert before invoking database hooks. Implementations may
    /// return `None` when no stable key is known before preparation.
    fn pending_account_key(&self, _user: &crate::AuthUser) -> Option<(String, String)> {
        None
    }

    async fn prepare_account(
        &self,
        context: DependentAccountContext<'_>,
    ) -> Result<DatabaseWrite<crate::OAuthAccount>, AuthError>;
}

/// Lazy ID preparation used by atomic create-if-missing operations.
///
/// The store invokes this only after it has established that an insert is
/// required, so reads and updates cannot accidentally consume generated IDs.
pub trait DatabaseIdSupplier: Send + Sync {
    fn prepare(&self) -> Result<PreparedDatabaseId, AuthError>;
}

impl<F> DatabaseIdSupplier for F
where
    F: Fn() -> Result<PreparedDatabaseId, AuthError> + Send + Sync,
{
    fn prepare(&self) -> Result<PreparedDatabaseId, AuthError> {
        self()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_outputs_match_javascript_string_conversion() {
        for (value, expected) in [
            (-0.0, "0"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (9_007_199_254_740_991.0, "9007199254740991"),
            (9_007_199_254_740_993.0, "9007199254740992"),
        ] {
            assert_eq!(
                DatabaseIdValue::Number(value).into_output_string(),
                expected
            );
        }
    }

    #[test]
    fn array_outputs_match_javascript_string_conversion() {
        for (value, expected) in [
            (serde_json::json!([]), ""),
            (serde_json::json!([null]), ""),
            (serde_json::json!([true, 7, "id"]), "true,7,id"),
            (serde_json::json!([[1], [2, 3]]), "1,2,3"),
            (serde_json::json!([{}]), "[object Object]"),
        ] {
            let serde_json::Value::Array(value) = value else {
                unreachable!("the fixture values are arrays")
            };
            assert_eq!(DatabaseIdValue::Array(value).into_output_string(), expected);
        }
    }
}
