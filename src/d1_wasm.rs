use indexmap::IndexMap;
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("authentication configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("authentication storage failed: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdditionalFieldType {
    String,
    Number,
    Boolean,
    Date,
    Json,
    StringArray,
    NumberArray,
    StringLiteral(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdditionalFieldOnDelete { NoAction, Restrict, Cascade, SetNull, SetDefault }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalFieldReference {
    pub model: String,
    pub field: String,
    pub on_delete: Option<AdditionalFieldOnDelete>,
}

pub trait AdditionalFieldDefault: Send + Sync {
    fn value(&self) -> Result<Value, AuthError>;
}

impl<F> AdditionalFieldDefault for F
where F: Fn() -> Result<Value, AuthError> + Send + Sync {
    fn value(&self) -> Result<Value, AuthError> { self() }
}

#[derive(Clone)]
pub struct AdditionalField {
    pub field_type: AdditionalFieldType,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
    pub field_name: Option<String>,
    pub references: Option<AdditionalFieldReference>,
    pub unique: bool,
    pub bigint: bool,
    pub sortable: bool,
    pub index: bool,
    default_value: Option<Value>,
    default_factory: Option<Arc<dyn AdditionalFieldDefault>>,
}

impl std::fmt::Debug for AdditionalField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AdditionalField")
            .field("field_type", &self.field_type).field("required", &self.required)
            .field("field_name", &self.field_name).field("references", &self.references)
            .field("unique", &self.unique).field("bigint", &self.bigint)
            .field("sortable", &self.sortable).field("index", &self.index).finish_non_exhaustive()
    }
}

impl AdditionalField {
    pub fn new(field_type: AdditionalFieldType) -> Self {
        Self { field_type, required: true, input: true, returned: true, field_name: None,
            references: None, unique: false, bigint: false, sortable: false, index: false,
            default_value: None, default_factory: None }
    }
    pub fn optional(mut self) -> Self { self.required = false; self }
    pub fn input(mut self, value: bool) -> Self { self.input = value; self }
    pub fn returned(mut self, value: bool) -> Self { self.returned = value; self }
    pub fn field_name(mut self, value: impl Into<String>) -> Self { self.field_name = Some(value.into()); self }
    pub fn references(mut self, value: AdditionalFieldReference) -> Self { self.references = Some(value); self }
    pub fn unique(mut self, value: bool) -> Self { self.unique = value; self }
    pub fn bigint(mut self, value: bool) -> Self { self.bigint = value; self }
    pub fn sortable(mut self, value: bool) -> Self { self.sortable = value; self }
    pub fn index(mut self, value: bool) -> Self { self.index = value; self }
    pub fn default_value(mut self, value: Value) -> Self { self.default_value = Some(value); self }
    pub fn default_with(mut self, value: Arc<dyn AdditionalFieldDefault>) -> Self { self.default_factory = Some(value); self }
    pub fn static_default_value(&self) -> Option<&Value> { self.default_value.as_ref() }
    pub fn has_default_factory(&self) -> bool { self.default_factory.is_some() }
    pub fn has_on_update(&self) -> bool { false }
    pub fn has_input_transform(&self) -> bool { false }
    pub fn has_output_transform(&self) -> bool { false }
    pub fn has_input_validator(&self) -> bool { false }
    pub fn has_output_validator(&self) -> bool { false }
}

pub type AdditionalFieldSet = IndexMap<String, AdditionalField>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DatabaseIdType { #[default] String, Serial, Uuid }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseIdGenerationKind { Default, Database, Serial, Uuid, Callback }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseSchemaIndex { pub name: Option<String>, pub fields: Vec<String>, pub unique: bool }

impl DatabaseSchemaIndex {
    pub fn new(fields: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { name: None, fields: fields.into_iter().map(Into::into).collect(), unique: false }
    }
    pub fn named(mut self, value: impl Into<String>) -> Self { self.name = Some(value.into()); self }
    pub fn unique(mut self, value: bool) -> Self { self.unique = value; self }
}

#[derive(Debug, Clone)]
pub struct SchemaTable {
    pub model_name: String,
    pub id_type: DatabaseIdType,
    pub fields: AdditionalFieldSet,
    pub indexes: Vec<DatabaseSchemaIndex>,
    pub disable_migrations: bool,
    pub order: Option<u32>,
}

impl SchemaTable {
    pub fn new(model_name: impl Into<String>, id_type: DatabaseIdType) -> Self {
        Self { model_name: model_name.into(), id_type, fields: IndexMap::new(), indexes: vec![], disable_migrations: false, order: None }
    }
    pub fn field(mut self, logical: impl Into<String>, field: AdditionalField) -> Self { self.fields.insert(logical.into(), field); self }
    pub fn index(mut self, index: DatabaseSchemaIndex) -> Self { self.indexes.push(index); self }
    pub fn disable_migrations(mut self, value: bool) -> Self { self.disable_migrations = value; self }
}

#[derive(Debug, Clone, Default)]
pub struct DatabaseModelSchema {
    pub model_name: Option<String>,
    pub fields: BTreeMap<String, String>,
    pub additional_fields: AdditionalFieldSet,
}

#[path = "database_schema/indexes.rs"] mod indexes;
pub use indexes::{ResolvedDatabaseIndex, SchemaIndexError};
#[path = "database_schema/fingerprint.rs"] mod fingerprint;
pub use fingerprint::SchemaFingerprint;

#[derive(Debug, Clone)]
pub struct AuthSchemaCatalog {
    tables: IndexMap<String, SchemaTable>,
    id_generation: DatabaseIdGenerationKind,
    indexes_by_table: IndexMap<String, Vec<ResolvedDatabaseIndex>>,
    field_indexes_by_table: IndexMap<String, Vec<ResolvedDatabaseIndex>>,
    fingerprint: SchemaFingerprint,
}

impl AuthSchemaCatalog {
    /// Builds the exact ordered catalog used by D1. Callers include every core
    /// and enabled plugin model; no legacy aliases are inferred.
    pub fn new(
        id_generation: DatabaseIdGenerationKind,
        tables: impl IntoIterator<Item = (String, SchemaTable)>,
    ) -> Result<Self, SchemaIndexError> {
        let mut catalog = Self { tables: tables.into_iter().collect(), id_generation,
            indexes_by_table: IndexMap::new(), field_indexes_by_table: IndexMap::new(),
            fingerprint: SchemaFingerprint(String::new()) };
        catalog.indexes_by_table = indexes::resolve(&catalog)?;
        catalog.field_indexes_by_table = indexes::resolve_field_indexes_for_adapter(&catalog, false)?;
        catalog.fingerprint = SchemaFingerprint::from_catalog(&catalog);
        Ok(catalog)
    }
    pub fn tables(&self) -> &IndexMap<String, SchemaTable> { &self.tables }
    pub fn table(&self, logical: &str) -> Option<&SchemaTable> { self.tables.get(logical) }
    pub fn fingerprint(&self) -> &SchemaFingerprint { &self.fingerprint }
    pub fn indexes_by_table(&self) -> &IndexMap<String, Vec<ResolvedDatabaseIndex>> { &self.indexes_by_table }
    pub fn field_indexes_by_table(&self) -> &IndexMap<String, Vec<ResolvedDatabaseIndex>> { &self.field_indexes_by_table }
    pub(crate) fn id_generation(&self) -> DatabaseIdGenerationKind { self.id_generation }
}

#[path = "database_schema/resolver.rs"] mod resolver;
pub use resolver::{AdapterSchemaOptions, ResolvedAdapterSchema, SchemaResolutionError};
