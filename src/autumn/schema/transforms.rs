use super::{
    SchemaError,
    engine::{Data, Outcome},
};
use serde_json::{Number, Value};

pub(super) fn coerce_number(outcome: Outcome, path: &str) -> Result<Outcome, SchemaError> {
    let Data::Value(Value::String(input)) = outcome.data else {
        return Err(SchemaError::new(path, "a numeric string"));
    };
    let number = parse_javascript_number(input.trim(), path)?;
    let value = if number.is_finite() {
        javascript_number(number, path)?
    } else {
        // JSON.stringify serializes non-finite JavaScript numbers as null at the HTTP boundary.
        Value::Null
    };
    Ok(Outcome {
        data: Data::Value(value),
        ..outcome
    })
}

fn parse_javascript_number(input: &str, path: &str) -> Result<f64, SchemaError> {
    if input.is_empty() {
        return Ok(0.0);
    }
    for (lower, upper, radix) in [("0x", "0X", 16), ("0b", "0B", 2), ("0o", "0O", 8)] {
        if let Some(digits) = input
            .strip_prefix(lower)
            .or_else(|| input.strip_prefix(upper))
        {
            return u64::from_str_radix(digits, radix)
                .map(|value| value as f64)
                .map_err(|_| SchemaError::new(path, "a numeric string"));
        }
    }
    input
        .parse::<f64>()
        .map_err(|_| SchemaError::new(path, "a numeric string"))
}

pub(super) fn coerce_boolean(outcome: Outcome, path: &str) -> Result<Outcome, SchemaError> {
    let Data::Value(Value::String(input)) = outcome.data else {
        return Err(SchemaError::new(path, "a boolean string"));
    };
    let value = match input.to_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => return Err(SchemaError::new(path, "a boolean string")),
    };
    Ok(Outcome {
        data: Data::Value(Value::Bool(value)),
        ..outcome
    })
}

pub(super) fn json_stringify(outcome: Outcome, path: &str) -> Result<Outcome, SchemaError> {
    let Data::Value(value) = outcome.data else {
        return Err(SchemaError::new(path, "a JSON value"));
    };
    let string = serde_json::to_string(&value)
        .map_err(|_| SchemaError::new(path, "a JSON-stringifiable value"))?;
    Ok(Outcome {
        data: Data::Value(Value::String(string)),
        ..outcome
    })
}

pub(super) fn normalize_untyped_data(data: Data) -> Data {
    match data {
        Data::Missing => Data::Missing,
        Data::Value(value) => Data::Value(normalize_untyped(value)),
    }
}

pub(super) fn normalize_untyped(value: Value) -> Value {
    match value {
        Value::Number(number) => normalize_untyped_number(number),
        Value::Array(values) => Value::Array(values.into_iter().map(normalize_untyped).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, normalize_untyped(value)))
                .collect(),
        ),
        value => value,
    }
}

fn normalize_untyped_number(number: Number) -> Value {
    let Some(value) = number.as_f64() else {
        return Value::Number(number);
    };
    javascript_number(value, "$").unwrap_or(Value::Number(number))
}

pub(super) fn javascript_number(value: f64, path: &str) -> Result<Value, SchemaError> {
    serde_json::from_str(ryu_js::Buffer::new().format(value))
        .map_err(|_| SchemaError::new(path, "a finite JavaScript number"))
}
