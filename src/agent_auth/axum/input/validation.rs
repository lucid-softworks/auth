use super::*;
use serde_json::Number;

pub(super) fn deserialize_validated<T: AgentInput>(
    mut value: Value,
    scope: &str,
) -> Result<T, AgentInputError> {
    validate_root::<T>(&mut value, scope)?;
    serde_json::from_value(value).map_err(|error| validation(format!("[{scope}] {error}")))
}

fn validate_root<T: AgentInput>(value: &mut Value, scope: &str) -> Result<(), AgentInputError> {
    let Value::Object(object) = value else {
        return Err(validation(format!(
            "[{scope}] Invalid input: expected object, received {}",
            received(value)
        )));
    };
    let mut issues = Vec::new();
    for field in T::FIELDS {
        match object.get_mut(field.name) {
            Some(value) => validate_field(field, value, scope, &mut issues),
            None if field.required => {
                issues.push(type_issue(scope, field.name, field.kind, "undefined"))
            }
            None => {}
        }
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(validation(issues.join("; ")))
    }
}

fn validate_field(field: &Field, value: &mut Value, scope: &str, issues: &mut Vec<String>) {
    if let FieldKind::Number { coerce: true, .. } = field.kind
        && let Value::String(raw) = value
    {
        match javascript_number(raw) {
            Some(number) => *value = Value::Number(number),
            None => {
                issues.push(type_issue(scope, field.name, field.kind, "NaN"));
                return;
            }
        }
    }
    if !matches_kind(value, field.kind) {
        issues.push(type_issue(scope, field.name, field.kind, received(value)));
        return;
    }
    validate_size(field, value, scope, issues);
    validate_nested(field, value, scope, issues);
}

fn validate_size(field: &Field, value: &Value, scope: &str, issues: &mut Vec<String>) {
    match (field.kind, value) {
        (FieldKind::String { min: Some(min) }, Value::String(value)) if value.len() < min => {
            issues.push(format!(
                "[{scope}.{}] Too small: expected string to have >={min} characters",
                field.name
            ));
        }
        (kind, Value::Array(value))
            if array_limits(kind)
                .is_some_and(|(min, _)| min.is_some_and(|min| value.len() < min)) =>
        {
            let min = array_limits(kind)
                .and_then(|(min, _)| min)
                .expect("matched");
            issues.push(format!(
                "[{scope}.{}] Too small: expected array to have >={min} items",
                field.name
            ));
        }
        (kind, Value::Array(value))
            if array_limits(kind)
                .is_some_and(|(_, max)| max.is_some_and(|max| value.len() > max)) =>
        {
            let max = array_limits(kind)
                .and_then(|(_, max)| max)
                .expect("matched");
            issues.push(format!(
                "[{scope}.{}] Too big: expected array to have <={max} items",
                field.name
            ));
        }
        (FieldKind::Number { min: Some(min), .. }, Value::Number(value))
            if value.as_f64().is_some_and(|value| {
                if min.inclusive {
                    value < min.value
                } else {
                    value <= min.value
                }
            }) =>
        {
            let comparison = if min.inclusive { ">=" } else { ">" };
            issues.push(format!(
                "[{scope}.{}] Too small: expected number to be {comparison}{}",
                field.name, min.value
            ));
        }
        (FieldKind::Url, Value::String(value)) if url::Url::parse(value).is_err() => {
            issues.push(format!("[{scope}.{}] Invalid URL", field.name));
        }
        _ => {}
    }
}

fn array_limits(kind: FieldKind) -> Option<(Option<usize>, Option<usize>)> {
    match kind {
        FieldKind::StringArray { min, max }
        | FieldKind::CapabilityArray { min, max }
        | FieldKind::BatchRequestArray { min, max } => Some((min, max)),
        _ => None,
    }
}

fn validate_nested(field: &Field, value: &Value, scope: &str, issues: &mut Vec<String>) {
    match (field.kind, value) {
        (FieldKind::StringArray { .. }, Value::Array(values)) => {
            for (index, value) in values.iter().enumerate() {
                if !value.is_string() {
                    issues.push(format!(
                        "[{scope}.{}.{index}] Invalid input: expected string, received {}",
                        field.name,
                        received(value)
                    ));
                }
            }
        }
        (FieldKind::CapabilityArray { .. }, Value::Array(values)) => {
            for (index, value) in values.iter().enumerate() {
                if serde_json::from_value::<crate::AgentCapabilityRequest>(value.clone()).is_err() {
                    issues.push(format!("[{scope}.{}.{index}] Invalid input", field.name));
                }
            }
        }
        (FieldKind::BatchRequestArray { .. }, Value::Array(values)) => {
            validate_batch_requests(field.name, values, scope, issues);
        }
        (FieldKind::JwkRecord, Value::Object(values)) => validate_jwk(field, values, scope, issues),
        (FieldKind::PrimitiveRecord, Value::Object(values)) => {
            for (name, value) in values {
                if !(value.is_string()
                    || value.is_number()
                    || value.is_boolean()
                    || value.is_null())
                {
                    issues.push(format!("[{scope}.{}.{name}] Invalid input", field.name));
                }
            }
        }
        _ => {}
    }
}

fn validate_jwk(field: &Field, values: &Map<String, Value>, scope: &str, issues: &mut Vec<String>) {
    for (name, value) in values {
        let valid = value.is_string()
            || value.is_boolean()
            || value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string));
        if !valid {
            issues.push(format!("[{scope}.{}.{name}] Invalid input", field.name));
        }
    }
}

fn validate_batch_requests(field: &str, values: &[Value], scope: &str, issues: &mut Vec<String>) {
    for (index, value) in values.iter().enumerate() {
        let Some(request) = value.as_object() else {
            issues.push(format!(
                "[{scope}.{field}.{index}] Invalid input: expected object, received {}",
                received(value)
            ));
            continue;
        };
        validate_nested_property(request, scope, field, index, "id", "string", false, issues);
        validate_nested_property(
            request,
            scope,
            field,
            index,
            "capability",
            "string",
            true,
            issues,
        );
        validate_nested_property(
            request,
            scope,
            field,
            index,
            "arguments",
            "record",
            false,
            issues,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_nested_property(
    request: &Map<String, Value>,
    scope: &str,
    field: &str,
    index: usize,
    name: &str,
    expected: &str,
    required: bool,
    issues: &mut Vec<String>,
) {
    let valid = |value: &Value| match expected {
        "string" => value.is_string(),
        "record" => value.is_object(),
        _ => false,
    };
    match request.get(name) {
        Some(value) if !valid(value) => issues.push(format!(
            "[{scope}.{field}.{index}.{name}] Invalid input: expected {expected}, received {}",
            received(value)
        )),
        None if required => issues.push(format!(
            "[{scope}.{field}.{index}.{name}] Invalid input: expected {expected}, received undefined"
        )),
        _ => {}
    }
}

fn matches_kind(value: &Value, kind: FieldKind) -> bool {
    match kind {
        FieldKind::String { .. } | FieldKind::Url => value.is_string(),
        FieldKind::Number { .. } => value.is_number(),
        FieldKind::Boolean => value.is_boolean(),
        FieldKind::StringArray { .. }
        | FieldKind::CapabilityArray { .. }
        | FieldKind::BatchRequestArray { .. } => value.is_array(),
        FieldKind::Record | FieldKind::PrimitiveRecord | FieldKind::JwkRecord => value.is_object(),
        FieldKind::Enum(options) => value.as_str().is_some_and(|value| options.contains(&value)),
    }
}

fn type_issue(scope: &str, name: &str, kind: FieldKind, actual: &str) -> String {
    if let FieldKind::Enum(options) = kind {
        return format!(
            "[{scope}.{name}] Invalid option: expected one of {}",
            options
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join("|")
        );
    }
    format!(
        "[{scope}.{name}] Invalid input: expected {}, received {actual}",
        expected(kind)
    )
}

fn expected(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::String { .. } | FieldKind::Url => "string",
        FieldKind::Number { .. } => "number",
        FieldKind::Boolean => "boolean",
        FieldKind::StringArray { .. }
        | FieldKind::CapabilityArray { .. }
        | FieldKind::BatchRequestArray { .. } => "array",
        FieldKind::Record | FieldKind::PrimitiveRecord | FieldKind::JwkRecord => "record",
        FieldKind::Enum(_) => "enum",
    }
}

fn received(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub(super) fn query_value(query: Option<&str>) -> Value {
    let mut values = Map::new();
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match values.entry(name.into_owned()) {
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(Value::String(value.into_owned()));
            }
            serde_json::map::Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(values) => values.push(Value::String(value.into_owned())),
                existing => {
                    let first = std::mem::take(existing);
                    *existing = Value::Array(vec![first, Value::String(value.into_owned())]);
                }
            },
        }
    }
    Value::Object(values)
}

fn javascript_number(value: &str) -> Option<Number> {
    let value = value.trim();
    let number = if value.is_empty() {
        0.0
    } else if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()? as f64
    } else {
        value.parse().ok()?
    };
    Number::from_f64(number)
}
