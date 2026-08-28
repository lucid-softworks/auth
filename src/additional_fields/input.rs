use super::{AdditionalField, AdditionalFieldSet};
use crate::AuthError;
use serde_json::{Map, Value};

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
        parsed.insert(name.clone(), process_input(name, field, value.clone())?);
    }
    for (name, field) in configured {
        if parsed.contains_key(name) || supplied.contains_key(name) {
            continue;
        }
        if let Some(factory) = &field.on_update {
            parsed.insert(name.clone(), process_input(name, field, factory.value()?)?);
        }
    }
    Ok(parsed)
}

pub(crate) fn validate_create_fields(
    configured: &AdditionalFieldSet,
    supplied: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    let mut parsed = Map::new();
    for (name, field) in configured {
        if let Some(value) = supplied.get(name) {
            if !field.input {
                if json_truthy(value) {
                    return Err(AuthError::InvalidRequest(format!(
                        "{name} is not allowed to be set"
                    )));
                }
            } else {
                if let Some(validator) = &field.input_validator {
                    validator
                        .validate(value)
                        .map_err(AuthError::InvalidRequest)?;
                }
                if !field.accepts(value) {
                    return Err(AuthError::InvalidRequest(format!(
                        "{name} has an invalid value"
                    )));
                }
                parsed.insert(name.clone(), value.clone());
                continue;
            }
        }
        if field.input && field.required && !field.has_default() {
            return Err(AuthError::InvalidRequest(format!("{name} is required")));
        }
    }
    Ok(parsed)
}

pub(crate) fn transform_create_fields(
    configured: &AdditionalFieldSet,
    supplied: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    let mut transformed = Map::new();
    for (name, field) in configured {
        let value = supplied.get(name).cloned().or(field.default()?);
        if let Some(value) = value {
            transformed.insert(name.clone(), process_input(name, field, value)?);
        }
    }
    Ok(transformed)
}

pub(crate) fn transform_update_hook_field(
    configured: &AdditionalFieldSet,
    name: &str,
    value: Option<Value>,
    undefined: bool,
) -> Result<Option<Value>, AuthError> {
    let Some(field) = configured.get(name) else {
        return Ok(None);
    };
    if undefined {
        return field
            .on_update
            .as_ref()
            .map(|factory| factory.value())
            .transpose()?
            .map(|value| process_input(name, field, value))
            .transpose();
    }
    value
        .map(|value| process_input(name, field, value))
        .transpose()
}

fn process_input(
    name: &str,
    field: &AdditionalField,
    mut value: Value,
) -> Result<Value, AuthError> {
    if let Some(validator) = &field.input_validator {
        validator
            .validate(&value)
            .map_err(AuthError::InvalidRequest)?;
    }
    if let Some(transform) = &field.input_transform {
        value = transform.transform(value)?;
    }
    if !field.accepts(&value) {
        return Err(AuthError::InvalidRequest(format!(
            "{name} has an invalid value"
        )));
    }
    Ok(value)
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
