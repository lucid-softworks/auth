use serde_json::{Map, Value};

#[derive(Debug)]
pub(super) struct InputError(String);

impl InputError {
    pub(super) fn message(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Default)]
pub(super) struct CancelInput {
    pub reason: Option<String>,
    pub immediate: Option<bool>,
}

#[derive(Debug)]
pub(super) struct UsageInput {
    pub feature: String,
    pub value: Option<serde_json::Number>,
    pub idempotency_key: Option<String>,
    pub properties: Option<Vec<(String, String)>>,
}

#[derive(Debug)]
pub(super) struct SeatInput {
    pub feature_code: String,
    pub count: serde_json::Number,
}

#[derive(Debug)]
pub(super) struct SetAllInput {
    pub seats: Map<String, Value>,
}

pub(super) fn cancel(value: Option<Value>) -> Result<CancelInput, InputError> {
    let Some(value) = value else {
        return Ok(CancelInput::default());
    };
    let body = object(value)?;
    let mut errors = Vec::new();
    let reason = capture(optional_string(&body, "reason"), &mut errors);
    let immediate = capture(optional_bool(&body, "immediate"), &mut errors);
    reject(errors)?;
    Ok(CancelInput {
        reason: reason.flatten(),
        immediate: immediate.flatten(),
    })
}

pub(super) fn usage(value: Option<Value>) -> Result<UsageInput, InputError> {
    let body = required_object(value)?;
    let mut errors = Vec::new();
    let feature = capture(required_string(&body, "feature"), &mut errors);
    let value = capture(optional_number(&body, "value"), &mut errors);
    let idempotency_key = capture(optional_string(&body, "idempotencyKey"), &mut errors);
    let properties = capture(optional_string_record(&body, "properties"), &mut errors);
    reject(errors)?;
    Ok(UsageInput {
        feature: feature.expect("required feature is present after validation"),
        value: value.flatten(),
        idempotency_key: idempotency_key.flatten(),
        properties: properties.flatten(),
    })
}

pub(super) fn seat(value: Option<Value>) -> Result<SeatInput, InputError> {
    let body = required_object(value)?;
    let mut errors = Vec::new();
    let feature_code = capture(required_string(&body, "featureCode"), &mut errors);
    let count = capture(seat_count(&body), &mut errors);
    reject(errors)?;
    Ok(SeatInput {
        feature_code: feature_code.expect("required feature code is present after validation"),
        count: count.expect("required count is present after validation"),
    })
}

pub(super) fn set_all(value: Option<Value>) -> Result<SetAllInput, InputError> {
    let body = required_object(value)?;
    let seats = match body.get("seats") {
        Some(Value::Object(values)) => {
            let mut errors = Vec::new();
            let mut seats = Map::new();
            for (key, value) in js_ordered_entries(values) {
                match value {
                    Value::Number(value) => {
                        if let Some(value) = javascript_number(value) {
                            seats.insert(key.clone(), Value::Number(value));
                        } else {
                            errors.push(invalid_number(&format!("body.seats.{key}")));
                        }
                    }
                    value => {
                        errors.push(expected(&format!("body.seats.{key}"), "number", value));
                    }
                }
            }
            reject(errors)?;
            seats
        }
        Some(value) => return Err(expected("body.seats", "record", value)),
        None => return Err(undefined("body.seats", "record")),
    };
    Ok(SetAllInput { seats })
}

fn capture<T>(result: Result<T, InputError>, errors: &mut Vec<InputError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(error);
            None
        }
    }
}

fn reject(errors: Vec<InputError>) -> Result<(), InputError> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(InputError(
            errors
                .into_iter()
                .map(|error| error.0)
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }
}

fn required_object(value: Option<Value>) -> Result<Map<String, Value>, InputError> {
    value
        .map(object)
        .unwrap_or_else(|| Err(undefined("body", "object")))
}

fn object(value: Value) -> Result<Map<String, Value>, InputError> {
    match value {
        Value::Object(body) => Ok(body),
        value => Err(expected("body", "object", &value)),
    }
}

fn required_string(body: &Map<String, Value>, key: &str) -> Result<String, InputError> {
    match body.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(value) => Err(expected(&format!("body.{key}"), "string", value)),
        None => Err(undefined(&format!("body.{key}"), "string")),
    }
}

fn optional_string(body: &Map<String, Value>, key: &str) -> Result<Option<String>, InputError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(value) => Err(expected(&format!("body.{key}"), "string", value)),
    }
}

fn optional_bool(body: &Map<String, Value>, key: &str) -> Result<Option<bool>, InputError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(value) => Err(expected(&format!("body.{key}"), "boolean", value)),
    }
}

fn required_number(body: &Map<String, Value>, key: &str) -> Result<serde_json::Number, InputError> {
    optional_number(body, key)?.ok_or_else(|| undefined(&format!("body.{key}"), "number"))
}

fn seat_count(body: &Map<String, Value>) -> Result<serde_json::Number, InputError> {
    let count = required_number(body, "count")?;
    if count.as_f64().is_some_and(|count| count < 1.0) {
        Err(InputError(
            "[body.count] Too small: expected number to be >=1".into(),
        ))
    } else {
        Ok(count)
    }
}

fn optional_number(
    body: &Map<String, Value>,
    key: &str,
) -> Result<Option<serde_json::Number>, InputError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Number(value)) => javascript_number(value)
            .map(Some)
            .ok_or_else(|| invalid_number(&format!("body.{key}"))),
        Some(value) => Err(expected(&format!("body.{key}"), "number", value)),
    }
}

fn javascript_number(number: &serde_json::Number) -> Option<serde_json::Number> {
    let value = number.as_f64()?;
    if !value.is_finite() {
        return None;
    }
    serde_json::from_str(ryu_js::Buffer::new().format(value)).ok()
}

fn optional_string_record(
    body: &Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<(String, String)>>, InputError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::Object(values)) => js_entries(values).map(Some),
        Some(value) => Err(expected(&format!("body.{key}"), "record", value)),
    }
}

fn js_entries(values: &Map<String, Value>) -> Result<Vec<(String, String)>, InputError> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (key, value) in js_ordered_entries(values) {
        match value {
            Value::String(value) => entries.push((key.clone(), value.clone())),
            value => errors.push(expected(&format!("body.properties.{key}"), "string", value)),
        }
    }
    reject(errors)?;
    Ok(entries)
}

fn js_ordered_entries(values: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut numeric = Vec::new();
    let mut other = Vec::new();
    for (key, value) in values {
        match array_index(key) {
            Some(index) => numeric.push((index, key, value)),
            None => other.push((key, value)),
        }
    }
    numeric.sort_by_key(|(index, _, _)| *index);
    numeric
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .chain(other)
        .collect()
}

fn array_index(value: &str) -> Option<u32> {
    if value.is_empty() || (value.starts_with('0') && value != "0") {
        return None;
    }
    let index = value.parse::<u32>().ok()?;
    (index != u32::MAX && index.to_string() == value).then_some(index)
}

fn undefined(path: &str, expected: &str) -> InputError {
    InputError(format!(
        "[{path}] Invalid input: expected {expected}, received undefined"
    ))
}

fn expected(path: &str, expected: &str, value: &Value) -> InputError {
    InputError(format!(
        "[{path}] Invalid input: expected {expected}, received {}",
        kind(value)
    ))
}

fn invalid_number(path: &str) -> InputError {
    InputError(format!(
        "[{path}] Invalid input: expected number, received number"
    ))
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
