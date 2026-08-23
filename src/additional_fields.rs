use crate::AuthError;
#[cfg(feature = "axum")]
use crate::{AuthSession, AuthUser};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

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
}

/// Input/output policy for a configured user or session additional field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalField {
    pub field_type: AdditionalFieldType,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
}

impl AdditionalField {
    pub fn new(field_type: AdditionalFieldType) -> Self {
        Self {
            field_type,
            required: true,
            input: true,
            returned: true,
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
            AdditionalFieldType::Json => value.is_object(),
            AdditionalFieldType::StringArray => value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)),
            AdditionalFieldType::NumberArray => value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_number)),
        }
    }
}

pub type AdditionalFieldSet = BTreeMap<String, AdditionalField>;

#[derive(Debug, Clone, Default)]
pub struct SessionConfig {
    pub additional_fields: AdditionalFieldSet,
}

pub(crate) fn parse_update_fields(
    configured: &AdditionalFieldSet,
    supplied: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    let mut parsed = Map::new();
    for (name, field) in configured {
        let Some(value) = supplied.get(name) else {
            continue;
        };
        if !field.input {
            if json_truthy(value) {
                return Err(AuthError::InvalidRequest(format!(
                    "{name} is not allowed to be set"
                )));
            }
            continue;
        }
        if !field.accepts(value) {
            return Err(AuthError::InvalidRequest(format!(
                "{name} has an invalid value"
            )));
        }
        parsed.insert(name.clone(), value.clone());
    }
    Ok(parsed)
}

pub(crate) fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_none_or(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[cfg(feature = "axum")]
pub(crate) fn filter_user_output(configured: &AdditionalFieldSet, user: &mut AuthUser) {
    filter_output(configured, &mut user.additional_fields);
}

#[cfg(feature = "axum")]
pub(crate) fn filter_session_output(configured: &AdditionalFieldSet, session: &mut AuthSession) {
    filter_output(configured, &mut session.additional_fields);
}

#[cfg(feature = "axum")]
fn filter_output(configured: &AdditionalFieldSet, values: &mut Map<String, Value>) {
    values.retain(|name, _| configured.get(name).is_none_or(|field| field.returned));
}

pub(crate) fn validate_field_names(
    model: &str,
    configured: &AdditionalFieldSet,
    reserved: &[&str],
) -> Result<(), AuthError> {
    if configured.keys().any(|name| {
        name.trim().is_empty()
            || reserved.contains(&name.as_str())
            || name.chars().any(|character| character.is_control())
    }) {
        return Err(AuthError::InvalidConfiguration(format!(
            "{model} additional field names must be non-empty and must not replace core fields"
        )));
    }
    Ok(())
}
