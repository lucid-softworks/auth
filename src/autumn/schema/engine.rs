use super::{
    SchemaError,
    catalog::CATALOG,
    catalog::Node,
    selection::{merge_data, normalize_union},
    transforms::{
        coerce_boolean, coerce_number, javascript_number, json_stringify, normalize_untyped,
        normalize_untyped_data,
    },
};
use serde_json::{Map, Value};

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, Clone)]
pub(super) enum Data {
    Missing,
    Value(Value),
}

#[derive(Debug)]
pub(super) struct Outcome {
    pub data: Data,
    pub inexact: usize,
    pub zero_defaults: usize,
}

impl Outcome {
    pub fn exact(data: Data) -> Self {
        Self {
            data,
            inexact: 0,
            zero_defaults: 0,
        }
    }
}

pub(super) fn normalize_root(value: Value, root: &str) -> Result<Value, SchemaError> {
    let node = CATALOG
        .roots
        .get(root)
        .copied()
        .ok_or_else(|| SchemaError::new("$", "a cataloged Autumn schema"))?;
    let outcome = normalize(node, Data::Value(value), "$", 0)?;
    match outcome.data {
        Data::Value(value) => Ok(value),
        Data::Missing => Err(SchemaError::new("$", "a JSON value")),
    }
}

pub(super) fn normalize(
    node_id: usize,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    if depth > 256 {
        return Err(SchemaError::new(
            path,
            "a payload nested at most 256 levels",
        ));
    }
    let node = CATALOG
        .nodes
        .get(node_id)
        .ok_or_else(|| SchemaError::new(path, "a valid catalog node"))?;
    match node {
        Node::Any | Node::Unknown => Ok(Outcome::exact(normalize_untyped_data(data))),
        Node::Boolean => primitive(data, path, Value::is_boolean, "boolean"),
        Node::String { format } => normalize_string(data, path, format.as_deref()),
        Node::Number { format } => normalize_number(data, path, format.as_deref()),
        Node::Null => primitive(data, path, Value::is_null, "null"),
        Node::Undefined => normalize_undefined(data, path),
        Node::Literal { values } => normalize_literal(data, values, path),
        Node::Nullable { inner } => normalize_nullable(*inner, data, path, depth),
        Node::Optional { inner } => normalize_optional(*inner, data, path, depth),
        Node::Default { inner, value } => normalize_default(*inner, value, data, path, depth),
        Node::ZeroDefault { value } => normalize_zero_default(value, data, path),
        Node::Array { element } => normalize_array(*element, data, path, depth),
        Node::Record { key, value } => normalize_record(*key, *value, data, path, depth),
        Node::Union { options } => normalize_union(options, data, path, depth, false),
        Node::SmartUnion { options } => normalize_union(options, data, path, depth, true),
        Node::Intersection { left, right } => {
            normalize_intersection(*left, *right, data, path, depth)
        }
        Node::Object { fields } => normalize_object(fields, data, path, depth),
        Node::Unrecognized { inner } => normalize_unrecognized(*inner, data, path, depth),
        Node::Reference { inner } => normalize(*inner, data, path, depth + 1),
        Node::ToUndefined { inner } => normalize_to_undefined(*inner, data, path, depth),
        Node::CoerceNumber { inner } => {
            normalize_transform(*inner, data, path, depth, coerce_number)
        }
        Node::CoerceBoolean { inner } => {
            normalize_transform(*inner, data, path, depth, coerce_boolean)
        }
        Node::JsonStringify { inner } => {
            normalize_transform(*inner, data, path, depth, json_stringify)
        }
    }
}

fn normalize_undefined(data: Data, path: &str) -> Result<Outcome, SchemaError> {
    match data {
        Data::Missing => Ok(Outcome::exact(Data::Missing)),
        Data::Value(value) => Err(SchemaError::invalid_type(
            path,
            "undefined",
            value_type(&value),
        )),
    }
}

fn normalize_nullable(
    inner: usize,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    match data {
        Data::Value(Value::Null) => Ok(Outcome::exact(Data::Value(Value::Null))),
        data => normalize(inner, data, path, depth + 1),
    }
}

fn normalize_optional(
    inner: usize,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    match data {
        Data::Missing => Ok(Outcome::exact(Data::Missing)),
        data => normalize(inner, data, path, depth + 1),
    }
}

fn normalize_default(
    inner: usize,
    value: &Value,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    match data {
        Data::Missing => normalize(inner, Data::Value(value.clone()), path, depth + 1),
        data => normalize(inner, data, path, depth + 1),
    }
}

fn normalize_zero_default(value: &Value, data: Data, path: &str) -> Result<Outcome, SchemaError> {
    match data {
        Data::Missing | Data::Value(Value::Null) => Ok(Outcome {
            data: Data::Value(value.clone()),
            inexact: 1,
            zero_defaults: 1,
        }),
        Data::Value(_) => Err(SchemaError::new(path, "null or an absent value")),
    }
}

fn normalize_intersection(
    left: usize,
    right: usize,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    let left = normalize(left, data.clone(), path, depth + 1)?;
    let right = normalize(right, data, path, depth + 1)?;
    Ok(Outcome {
        data: merge_data(left.data, right.data, path)?,
        inexact: left.inexact + right.inexact,
        zero_defaults: left.zero_defaults + right.zero_defaults,
    })
}

fn normalize_unrecognized(
    inner: usize,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    let mut outcome = normalize(inner, data, path, depth + 1)?;
    outcome.inexact += 1;
    Ok(outcome)
}

fn normalize_to_undefined(
    inner: usize,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    normalize(inner, data, path, depth + 1)?;
    Ok(Outcome {
        data: Data::Missing,
        inexact: 1,
        zero_defaults: 0,
    })
}

fn normalize_transform(
    inner: usize,
    data: Data,
    path: &str,
    depth: usize,
    transform: fn(Outcome, &str) -> Result<Outcome, SchemaError>,
) -> Result<Outcome, SchemaError> {
    transform(normalize(inner, data, path, depth + 1)?, path)
}

fn primitive(
    data: Data,
    path: &str,
    predicate: impl FnOnce(&Value) -> bool,
    expected: &'static str,
) -> Result<Outcome, SchemaError> {
    let received = received_type(&data);
    let Data::Value(value) = data else {
        return Err(SchemaError::invalid_type(path, expected, received));
    };
    predicate(&value)
        .then_some(Outcome::exact(Data::Value(value)))
        .ok_or_else(|| SchemaError::invalid_type(path, expected, received))
}

fn normalize_string(data: Data, path: &str, _format: Option<&str>) -> Result<Outcome, SchemaError> {
    primitive(data, path, Value::is_string, "string")
}

fn normalize_number(data: Data, path: &str, format: Option<&str>) -> Result<Outcome, SchemaError> {
    let Data::Value(value) = data else {
        return Err(SchemaError::invalid_type(path, "number", "undefined"));
    };
    let Some(input) = value.as_f64() else {
        return Err(SchemaError::invalid_type(
            path,
            "number",
            value_type(&value),
        ));
    };
    if format == Some("safeint") && (input.fract() != 0.0 || input.abs() > MAX_SAFE_INTEGER) {
        return Err(SchemaError::invalid_type(path, "safeint", "number"));
    }
    Ok(Outcome::exact(Data::Value(javascript_number(input, path)?)))
}

fn normalize_literal(data: Data, literals: &[Value], path: &str) -> Result<Outcome, SchemaError> {
    let Data::Value(value) = normalize_untyped_data(data) else {
        return Err(SchemaError::invalid_value(path, literals.to_vec()));
    };
    literals
        .iter()
        .any(|literal| normalize_untyped(literal.clone()) == value)
        .then_some(Outcome::exact(Data::Value(value)))
        .ok_or_else(|| SchemaError::invalid_value(path, literals.to_vec()))
}

fn normalize_array(
    element: usize,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    let received = received_type(&data);
    let Data::Value(Value::Array(values)) = data else {
        return Err(SchemaError::invalid_type(path, "array", received));
    };
    let mut output = Vec::with_capacity(values.len());
    let mut inexact = 0;
    let mut zero_defaults = 0;
    for (index, value) in values.into_iter().enumerate() {
        let item = normalize(
            element,
            Data::Value(value),
            &format!("{path}[{index}]"),
            depth + 1,
        )?;
        let Data::Value(value) = item.data else {
            return Err(SchemaError::new(
                format!("{path}[{index}]"),
                "a JSON array value",
            ));
        };
        output.push(value);
        inexact += item.inexact;
        zero_defaults += item.zero_defaults;
    }
    Ok(Outcome {
        data: Data::Value(Value::Array(output)),
        inexact,
        zero_defaults,
    })
}

fn normalize_record(
    key: usize,
    item: usize,
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    let received = received_type(&data);
    let Data::Value(Value::Object(values)) = data else {
        return Err(SchemaError::invalid_type(path, "record", received));
    };
    let mut output = Map::with_capacity(values.len());
    let mut inexact = 0;
    let mut zero_defaults = 0;
    for (name, value) in values {
        let field_path = format!("{path}.{name}");
        let normalized_key = normalize(
            key,
            Data::Value(Value::String(name)),
            &field_path,
            depth + 1,
        )?;
        let Data::Value(Value::String(name)) = normalized_key.data else {
            return Err(SchemaError::new(field_path, "a string record key"));
        };
        let normalized = normalize(item, Data::Value(value), &field_path, depth + 1)?;
        let Data::Value(value) = normalized.data else {
            continue;
        };
        output.insert(name, value);
        inexact += normalized_key.inexact + normalized.inexact;
        zero_defaults += normalized_key.zero_defaults + normalized.zero_defaults;
    }
    Ok(Outcome {
        data: Data::Value(Value::Object(output)),
        inexact,
        zero_defaults,
    })
}

fn normalize_object(
    fields: &[super::catalog::Field],
    data: Data,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    let received = received_type(&data);
    let Data::Value(Value::Object(mut values)) = data else {
        return Err(SchemaError::invalid_type(path, "object", received));
    };
    let mut output = Map::with_capacity(fields.len());
    let mut inexact = 0;
    let mut zero_defaults = 0;
    for field in fields {
        let field_path = format!("{path}.{}", field.input);
        let data = values
            .shift_remove(&field.input)
            .map_or(Data::Missing, Data::Value);
        let normalized = normalize(field.schema, data, &field_path, depth + 1)?;
        if let Data::Value(value) = normalized.data {
            output.insert(field.output.clone(), value);
        }
        inexact += normalized.inexact;
        zero_defaults += normalized.zero_defaults;
    }
    Ok(Outcome {
        data: Data::Value(Value::Object(output)),
        inexact,
        zero_defaults,
    })
}

fn received_type(data: &Data) -> &'static str {
    match data {
        Data::Missing => "undefined",
        Data::Value(value) => value_type(value),
    }
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
