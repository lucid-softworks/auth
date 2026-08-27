use crate::AuthError;
#[cfg(feature = "axum")]
use crate::{AuthSession, AuthUser};
use serde_json::{Map, Value};
use std::{fmt, sync::Arc};

mod input;
mod validation;

#[cfg(feature = "axum")]
pub(crate) use input::json_truthy;
pub(crate) use input::{
    parse_update_fields, transform_create_fields, transform_update_hook_field,
    validate_create_fields,
};

pub(crate) use validation::{reserved_field_names, validate_field_names};

/// Better Auth-compatible primitive type for an additional database field.
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

/// Input/output policy for a configured user or session additional field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalFieldReference {
    pub model: String,
    pub field: String,
    pub on_delete: Option<AdditionalFieldOnDelete>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdditionalFieldOnDelete {
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

pub trait AdditionalFieldDefault: Send + Sync {
    fn value(&self) -> Result<Value, AuthError>;
}

impl<F> AdditionalFieldDefault for F
where
    F: Fn() -> Result<Value, AuthError> + Send + Sync,
{
    fn value(&self) -> Result<Value, AuthError> {
        self()
    }
}

pub trait AdditionalFieldTransform: Send + Sync {
    fn transform(&self, value: Value) -> Result<Value, AuthError>;
}

impl<F> AdditionalFieldTransform for F
where
    F: Fn(Value) -> Result<Value, AuthError> + Send + Sync,
{
    fn transform(&self, value: Value) -> Result<Value, AuthError> {
        self(value)
    }
}

pub trait AdditionalFieldValidator: Send + Sync {
    fn validate(&self, value: &Value) -> Result<(), String>;
}

impl<F> AdditionalFieldValidator for F
where
    F: Fn(&Value) -> Result<(), String> + Send + Sync,
{
    fn validate(&self, value: &Value) -> Result<(), String> {
        self(value)
    }
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
    on_update: Option<Arc<dyn AdditionalFieldDefault>>,
    input_transform: Option<Arc<dyn AdditionalFieldTransform>>,
    output_transform: Option<Arc<dyn AdditionalFieldTransform>>,
    input_validator: Option<Arc<dyn AdditionalFieldValidator>>,
    output_validator: Option<Arc<dyn AdditionalFieldValidator>>,
}

impl fmt::Debug for AdditionalField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdditionalField")
            .field("field_type", &self.field_type)
            .field("required", &self.required)
            .field("input", &self.input)
            .field("returned", &self.returned)
            .field("field_name", &self.field_name)
            .field("references", &self.references)
            .field("unique", &self.unique)
            .field("bigint", &self.bigint)
            .field("sortable", &self.sortable)
            .field("index", &self.index)
            .field("default_value", &self.default_value)
            .field("has_default_factory", &self.default_factory.is_some())
            .field("has_on_update", &self.on_update.is_some())
            .field("has_input_transform", &self.input_transform.is_some())
            .field("has_output_transform", &self.output_transform.is_some())
            .field("has_input_validator", &self.input_validator.is_some())
            .field("has_output_validator", &self.output_validator.is_some())
            .finish()
    }
}

impl AdditionalField {
    pub fn new(field_type: AdditionalFieldType) -> Self {
        Self {
            field_type,
            required: true,
            input: true,
            returned: true,
            field_name: None,
            references: None,
            unique: false,
            bigint: false,
            sortable: false,
            index: false,
            default_value: None,
            default_factory: None,
            on_update: None,
            input_transform: None,
            output_transform: None,
            input_validator: None,
            output_validator: None,
        }
    }

    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    pub fn input(mut self, input: bool) -> Self {
        self.input = input;
        self
    }

    pub fn returned(mut self, returned: bool) -> Self {
        self.returned = returned;
        self
    }

    pub fn default_value(mut self, value: Value) -> Self {
        self.default_value = Some(value);
        self.default_factory = None;
        self
    }

    pub fn default_with(mut self, factory: Arc<dyn AdditionalFieldDefault>) -> Self {
        self.default_factory = Some(factory);
        self.default_value = None;
        self
    }

    pub fn on_update_with(mut self, factory: Arc<dyn AdditionalFieldDefault>) -> Self {
        self.on_update = Some(factory);
        self
    }

    pub fn transform_input(mut self, transform: Arc<dyn AdditionalFieldTransform>) -> Self {
        self.input_transform = Some(transform);
        self
    }

    pub fn transform_output(mut self, transform: Arc<dyn AdditionalFieldTransform>) -> Self {
        self.output_transform = Some(transform);
        self
    }

    pub fn validate_input(mut self, validator: Arc<dyn AdditionalFieldValidator>) -> Self {
        self.input_validator = Some(validator);
        self
    }

    pub fn validate_output(mut self, validator: Arc<dyn AdditionalFieldValidator>) -> Self {
        self.output_validator = Some(validator);
        self
    }

    pub fn field_name(mut self, name: impl Into<String>) -> Self {
        self.field_name = Some(name.into());
        self
    }

    pub fn references(mut self, reference: AdditionalFieldReference) -> Self {
        self.references = Some(reference);
        self
    }

    pub fn unique(mut self, unique: bool) -> Self {
        self.unique = unique;
        self
    }

    pub fn bigint(mut self, bigint: bool) -> Self {
        self.bigint = bigint;
        self
    }

    pub fn sortable(mut self, sortable: bool) -> Self {
        self.sortable = sortable;
        self
    }

    pub fn index(mut self, index: bool) -> Self {
        self.index = index;
        self
    }

    pub fn has_default(&self) -> bool {
        self.default_value.is_some() || self.default_factory.is_some()
    }

    pub(crate) fn has_default_factory(&self) -> bool {
        self.default_factory.is_some()
    }

    pub(crate) fn has_on_update(&self) -> bool {
        self.on_update.is_some()
    }

    pub(crate) fn has_input_transform(&self) -> bool {
        self.input_transform.is_some()
    }

    pub(crate) fn has_output_transform(&self) -> bool {
        self.output_transform.is_some()
    }

    pub(crate) fn has_input_validator(&self) -> bool {
        self.input_validator.is_some()
    }

    pub(crate) fn has_output_validator(&self) -> bool {
        self.output_validator.is_some()
    }

    /// Returns only a static default. Runtime factories are deliberately not
    /// evaluated while generating database or request documentation.
    pub fn static_default_value(&self) -> Option<&Value> {
        self.default_value.as_ref()
    }

    fn default(&self) -> Result<Option<Value>, AuthError> {
        self.default_factory
            .as_ref()
            .map(|factory| factory.value())
            .transpose()
            .map(|dynamic| dynamic.or_else(|| self.default_value.clone()))
    }

    fn accepts(&self, value: &Value) -> bool {
        if value.is_null() {
            return !self.required;
        }
        match self.field_type {
            AdditionalFieldType::String => value.is_string(),
            AdditionalFieldType::Number => value.is_number(),
            AdditionalFieldType::Boolean => value.is_boolean(),
            AdditionalFieldType::Date => value
                .as_str()
                .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok()),
            AdditionalFieldType::Json => value.is_object() || value.is_array(),
            AdditionalFieldType::StringArray => value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)),
            AdditionalFieldType::NumberArray => value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_number)),
            AdditionalFieldType::StringLiteral(values) => {
                value.as_str().is_some_and(|value| values.contains(&value))
            }
        }
    }
}

/// Ordered Better Auth additional fields. JavaScript object insertion order is
/// observable during schema merging and reverse physical-name lookup.
pub type AdditionalFieldSet = indexmap::IndexMap<String, AdditionalField>;

#[cfg(feature = "axum")]
pub(crate) fn filter_user_output(configured: &AdditionalFieldSet, user: &mut AuthUser) {
    filter_output(configured, &mut user.additional_fields);
}

#[cfg(feature = "axum")]
pub(crate) fn filter_session_output(configured: &AdditionalFieldSet, session: &mut AuthSession) {
    filter_output(configured, &mut session.additional_fields);
}

fn filter_output(configured: &AdditionalFieldSet, values: &mut Map<String, Value>) {
    values.retain(|name, value| {
        let Some(field) = configured.get(name) else {
            return true;
        };
        if !field.returned {
            return false;
        }
        if let Some(transform) = &field.output_transform {
            let Ok(transformed) = transform.transform(value.clone()) else {
                return false;
            };
            *value = transformed;
        }
        field
            .output_validator
            .as_ref()
            .is_none_or(|validator| validator.validate(value).is_ok())
    });
}

pub(crate) fn filtered_output(
    configured: &AdditionalFieldSet,
    mut values: Map<String, Value>,
) -> Map<String, Value> {
    filter_output(configured, &mut values);
    values
}
