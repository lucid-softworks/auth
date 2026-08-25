use serde_json::{Map, Value};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DodoInputError {
    pub(super) message: String,
}

impl DodoInputError {
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DodoInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DodoInputError {}

#[derive(Clone, Copy)]
pub(super) enum NumberRule {
    Any,
    Integer,
    NonnegativeInteger,
    PositiveInteger,
}

#[derive(Clone, Copy)]
pub(super) enum StringRule {
    Any,
    Nonempty(&'static str),
    Length(usize),
    Url,
}

pub(super) fn root_object(value: Value) -> Result<Map<String, Value>, DodoInputError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| expected("body", "object", &value))
}

pub(super) fn require_together(
    map: &Map<String, Value>,
    keys: &[&str],
) -> Result<(), DodoInputError> {
    let missing = keys
        .iter()
        .filter(|key| !map.contains_key(**key))
        .map(|key| format!("[body.{key}] Required"))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(error(missing.join("; ")))
    }
}

pub(super) fn optional_string(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
    nullable: bool,
) -> Result<(), DodoInputError> {
    optional_string_rule(map, key, path, nullable, StringRule::Any)
}

pub(super) fn optional_string_rule(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
    nullable: bool,
    rule: StringRule,
) -> Result<(), DodoInputError> {
    let Some(value) = map.get(key) else {
        return Ok(());
    };
    if nullable && value.is_null() {
        return Ok(());
    }
    let text = value
        .as_str()
        .ok_or_else(|| expected(path, "string", value))?;
    validate_string(text, path, rule)
}

pub(super) fn required_string_value(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<String, DodoInputError> {
    let value = map
        .get(key)
        .ok_or_else(|| error(format!("[{path}] Required")))?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| expected(path, "string", value))
}

pub(super) fn optional_bool(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
    nullable: bool,
) -> Result<(), DodoInputError> {
    let Some(value) = map.get(key) else {
        return Ok(());
    };
    if nullable && value.is_null() {
        return Ok(());
    }
    if value.is_boolean() {
        Ok(())
    } else {
        Err(expected(path, "boolean", value))
    }
}

pub(super) fn optional_number(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
    rule: NumberRule,
    nullable: bool,
) -> Result<(), DodoInputError> {
    let Some(value) = map.get(key) else {
        return Ok(());
    };
    if nullable && value.is_null() {
        return Ok(());
    }
    validate_number(value, path, rule)
}

fn validate_number(value: &Value, path: &str, rule: NumberRule) -> Result<(), DodoInputError> {
    let number = value
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| expected(path, "number", value))?;
    let valid = match rule {
        NumberRule::Any => true,
        NumberRule::Integer => number.fract() == 0.0,
        NumberRule::NonnegativeInteger => number.fract() == 0.0 && number >= 0.0,
        NumberRule::PositiveInteger => number.fract() == 0.0 && number > 0.0,
    };
    if valid {
        Ok(())
    } else {
        Err(error(format!("[{path}] Invalid number")))
    }
}

fn validate_string(value: &str, path: &str, rule: StringRule) -> Result<(), DodoInputError> {
    let valid = match rule {
        StringRule::Any => true,
        StringRule::Nonempty(_) => !value.is_empty(),
        StringRule::Length(length) => value.encode_utf16().count() == length,
        StringRule::Url => url::Url::parse(value).is_ok(),
    };
    if valid {
        return Ok(());
    }
    let message: String = match rule {
        StringRule::Nonempty(message) => message.into(),
        StringRule::Length(2) => "Country must be a 2-letter ISO code".into(),
        StringRule::Length(3) => "Currency must be a 3-letter ISO code".into(),
        StringRule::Url => "Invalid url".into(),
        _ => "Invalid input".into(),
    };
    Err(error(format!("[{path}] {message}")))
}

pub(super) fn string<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

pub(super) fn object_mut_at<'a>(
    value: &'a mut Value,
    path: &str,
) -> Result<&'a mut Map<String, Value>, DodoInputError> {
    if !value.is_object() {
        return Err(expected(path, "object", value));
    }
    Ok(value.as_object_mut().expect("object checked"))
}

pub(super) fn array_mut_at<'a>(
    value: &'a mut Value,
    path: &str,
) -> Result<&'a mut Vec<Value>, DodoInputError> {
    if !value.is_array() {
        return Err(expected(path, "array", value));
    }
    Ok(value.as_array_mut().expect("array checked"))
}

pub(super) fn error(message: String) -> DodoInputError {
    DodoInputError { message }
}

pub(super) fn expected(path: &str, expected_type: &str, value: &Value) -> DodoInputError {
    error(format!(
        "[{path}] Expected {expected_type}, received {}",
        value_type(value)
    ))
}

pub(super) fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub(super) fn email_is_valid(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    let labels = domain.split('.').collect::<Vec<_>>();
    !local.is_empty()
        && !local.starts_with('.')
        && !local.contains("..")
        && local.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '\'' | '+' | '-' | '.')
        })
        && local.chars().next_back().is_some_and(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '+' | '-')
        })
        && labels.len() >= 2
        && labels[..labels.len() - 1].iter().all(|label| {
            label
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_alphanumeric())
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        && labels.last().is_some_and(|label| {
            label.len() >= 2
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphabetic())
        })
}

pub(super) fn normalize_discount_codes(
    body: &mut Map<String, Value>,
    key: &str,
    path: &str,
    nullable: bool,
) -> Result<(), DodoInputError> {
    optional_string_array(body, key, path, nullable, true)?;
    let Some(Value::Array(codes)) = body.get(key) else {
        return Ok(());
    };
    if codes.len() > 20 {
        return Err(error(format!(
            "[{path}] At most 20 stacked discount codes are allowed"
        )));
    }
    for (index, code) in codes.iter().enumerate() {
        if code.as_str().is_some_and(str::is_empty) {
            return Err(error(format!(
                "[{path}.{index}] Discount code cannot be empty"
            )));
        }
    }
    Ok(())
}

pub(super) fn normalize_record(
    body: &mut Map<String, Value>,
    key: &str,
    path: &str,
    nullable: bool,
) -> Result<(), DodoInputError> {
    let Some(value) = body.get(key) else {
        return Ok(());
    };
    if nullable && value.is_null() {
        return Ok(());
    }
    let values = value
        .as_object()
        .ok_or_else(|| expected(path, "object", value))?;
    if let Some((record_key, invalid)) = values.iter().find(|(_, value)| !is_metadata_value(value))
    {
        return Err(error(format!(
            "[{path}.{record_key}] Expected string, number, or boolean, received {}",
            value_type(invalid)
        )));
    }
    Ok(())
}

pub(super) fn is_metadata_value(value: &Value) -> bool {
    value.is_string() || value.is_number() || value.is_boolean()
}

pub(super) fn optional_string_array(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
    nullable: bool,
    allow_empty: bool,
) -> Result<(), DodoInputError> {
    let Some(value) = map.get(key) else {
        return Ok(());
    };
    if nullable && value.is_null() {
        return Ok(());
    }
    let values = value
        .as_array()
        .ok_or_else(|| expected(path, "array", value))?;
    for (index, value) in values.iter().enumerate() {
        let text = value
            .as_str()
            .ok_or_else(|| expected(&format!("{path}.{index}"), "string", value))?;
        if !allow_empty && text.is_empty() {
            return Err(error(format!("[{path}.{index}] Invalid input")));
        }
    }
    Ok(())
}

pub(super) fn enum_string(
    map: &Map<String, Value>,
    key: &str,
    path: &str,
    allowed: &str,
    nullable: bool,
) -> Result<(), DodoInputError> {
    let Some(value) = map.get(key) else {
        return Ok(());
    };
    if nullable && value.is_null() {
        return Ok(());
    }
    let text = value
        .as_str()
        .ok_or_else(|| expected(path, "string", value))?;
    if allowed.split('|').any(|candidate| candidate == text) {
        Ok(())
    } else {
        Err(error(format!("[{path}] Invalid enum value")))
    }
}

pub(super) fn require_nested(
    map: &Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<(), DodoInputError> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(error(format!("[{parent}.{key}] Required")))
    }
}

pub(super) fn prefix_nested_error(error: DodoInputError, parent: &str) -> DodoInputError {
    DodoInputError {
        message: error.message.replace("[body.", &format!("[body.{parent}.")),
    }
}
