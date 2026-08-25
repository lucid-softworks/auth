use super::{SchemaError, catalog::CATALOG, catalog::Node};
use chrono::{DateTime, SecondsFormat};
use regex::Regex;
use serde_json::{Map, Number, Value};
use std::sync::LazyLock;

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

static SDK_DATETIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|",
        r"[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|",
        r"(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))T",
        r"(?:(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?",
        r"(?:Z|([+-](?:[01]\d|2[0-3]):[0-5]\d)))$"
    ))
    .expect("the pinned SDK datetime expression is valid")
});

#[derive(Debug)]
struct Outcome {
    value: Value,
    inexact: usize,
}

pub(super) fn normalize_root(value: Value, root: &str) -> Result<Value, SchemaError> {
    let node = CATALOG
        .roots
        .get(root)
        .copied()
        .ok_or_else(|| SchemaError::new("$", "a cataloged SDK schema"))?;
    normalize(node, value, "$", 0).map(|outcome| outcome.value)
}

fn normalize(
    node_id: usize,
    value: Value,
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
        Node::Any | Node::Unknown => Ok(Outcome {
            value: normalize_untyped(value),
            inexact: 0,
        }),
        Node::Boolean => primitive(value, path, Value::is_boolean, "a boolean"),
        Node::String { format } => {
            if !value.is_string() {
                return Err(SchemaError::new(path, "a string"));
            }
            if format.as_deref() == Some("datetime") {
                canonical_date(value, path)
            } else {
                Ok(Outcome { value, inexact: 0 })
            }
        }
        Node::Number { format } => normalize_number(value, path, format.as_deref()),
        Node::Date => canonical_date(value, path),
        Node::Literal { values } => normalize_literal(value, values, path),
        Node::Nullable { inner } => {
            if value.is_null() {
                Ok(Outcome { value, inexact: 0 })
            } else {
                normalize(*inner, value, path, depth + 1)
            }
        }
        Node::Optional { inner } | Node::Default { inner, .. } | Node::Reference { inner } => {
            normalize(*inner, value, path, depth + 1)
        }
        Node::Array { element } => normalize_array(*element, value, path, depth),
        Node::Record { key, value: item } => normalize_record(*key, *item, value, path, depth),
        Node::Union { options } => normalize_union(options, value, path, depth, false),
        Node::SmartUnion { options } => normalize_union(options, value, path, depth, true),
        Node::Intersection { left, right } => {
            let left = normalize(*left, value.clone(), path, depth + 1)?;
            let right = normalize(*right, value, path, depth + 1)?;
            Ok(Outcome {
                value: merge(left.value, right.value, path)?,
                inexact: left.inexact + right.inexact,
            })
        }
        Node::Object { fields } => normalize_object(fields, value, path, depth),
        Node::Unrecognized { inner } => {
            let mut outcome = normalize(*inner, value, path, depth + 1)?;
            outcome.inexact += 1;
            Ok(outcome)
        }
    }
}

fn primitive(
    value: Value,
    path: &str,
    predicate: impl FnOnce(&Value) -> bool,
    expected: &'static str,
) -> Result<Outcome, SchemaError> {
    predicate(&value)
        .then_some(Outcome { value, inexact: 0 })
        .ok_or_else(|| SchemaError::new(path, expected))
}

fn normalize_number(
    value: Value,
    path: &str,
    format: Option<&str>,
) -> Result<Outcome, SchemaError> {
    let Some(input) = value.as_f64() else {
        return Err(SchemaError::new(path, "a number"));
    };
    if format == Some("safeint") && (input.fract() != 0.0 || input.abs() > MAX_SAFE_INTEGER) {
        return Err(SchemaError::new(path, "a safe integer"));
    }
    let mut buffer = ryu_js::Buffer::new();
    let text = buffer.format(input);
    let value = serde_json::from_str(text).map_err(|_| SchemaError::new(path, "a number"))?;
    Ok(Outcome { value, inexact: 0 })
}

fn normalize_literal(value: Value, literals: &[Value], path: &str) -> Result<Outcome, SchemaError> {
    let value = normalize_untyped(value);
    literals
        .iter()
        .any(|literal| normalize_untyped(literal.clone()) == value)
        .then_some(Outcome { value, inexact: 0 })
        .ok_or_else(|| SchemaError::new(path, "a schema literal"))
}

fn canonical_date(value: Value, path: &str) -> Result<Outcome, SchemaError> {
    let Some(input) = value.as_str() else {
        return Err(SchemaError::new(path, "an RFC 3339 datetime"));
    };
    if !SDK_DATETIME.is_match(input) {
        return Err(SchemaError::new(path, "an RFC 3339 datetime"));
    }
    let date = DateTime::parse_from_rfc3339(input)
        .map_err(|_| SchemaError::new(path, "an RFC 3339 datetime"))?;
    Ok(Outcome {
        value: Value::String(
            date.with_timezone(&chrono::Utc)
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        ),
        inexact: 0,
    })
}

fn normalize_array(
    element: usize,
    value: Value,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    let Value::Array(values) = value else {
        return Err(SchemaError::new(path, "an array"));
    };
    let mut output = Vec::with_capacity(values.len());
    let mut inexact = 0;
    for (index, value) in values.into_iter().enumerate() {
        let item = normalize(element, value, &format!("{path}[{index}]"), depth + 1)?;
        output.push(item.value);
        inexact += item.inexact;
    }
    Ok(Outcome {
        value: Value::Array(output),
        inexact,
    })
}

fn normalize_record(
    key: usize,
    item: usize,
    value: Value,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    let Value::Object(values) = value else {
        return Err(SchemaError::new(path, "an object record"));
    };
    let mut output = Map::with_capacity(values.len());
    let mut inexact = 0;
    for (name, value) in values {
        let field_path = format!("{path}.{name}");
        let normalized_key = normalize(key, Value::String(name), &field_path, depth + 1)?;
        let Some(name) = normalized_key.value.as_str().map(str::to_owned) else {
            return Err(SchemaError::new(field_path, "a string record key"));
        };
        let normalized = normalize(item, value, &field_path, depth + 1)?;
        output.insert(name, normalized.value);
        inexact += normalized_key.inexact + normalized.inexact;
    }
    Ok(Outcome {
        value: Value::Object(output),
        inexact,
    })
}

fn normalize_object(
    fields: &[super::catalog::Field],
    value: Value,
    path: &str,
    depth: usize,
) -> Result<Outcome, SchemaError> {
    let Value::Object(mut values) = value else {
        return Err(SchemaError::new(path, "an object"));
    };
    let mut output = Map::with_capacity(fields.len());
    let mut inexact = 0;
    for field in fields {
        let field_path = format!("{path}.{}", field.input);
        let normalized = match values.remove(&field.input) {
            Some(value) => normalize(field.schema, value, &field_path, depth + 1)?,
            None => match missing(field.schema, &field_path, depth + 1)? {
                Some(value) => value,
                None => continue,
            },
        };
        output.insert(field.output.clone(), normalized.value);
        inexact += normalized.inexact;
    }
    Ok(Outcome {
        value: Value::Object(output),
        inexact,
    })
}

fn missing(node_id: usize, path: &str, depth: usize) -> Result<Option<Outcome>, SchemaError> {
    match &CATALOG.nodes[node_id] {
        Node::Optional { .. } => Ok(None),
        Node::Default { inner, value } => {
            normalize(*inner, value.clone(), path, depth + 1).map(Some)
        }
        _ => Err(SchemaError::new(path, "a required field")),
    }
}

fn normalize_union(
    options: &[usize],
    value: Value,
    path: &str,
    depth: usize,
    smart: bool,
) -> Result<Outcome, SchemaError> {
    let mut candidates = options
        .iter()
        .filter_map(|option| normalize(*option, value.clone(), path, depth + 1).ok());
    let Some(mut best) = candidates.next() else {
        return Err(SchemaError::new(path, "a matching union member"));
    };
    if !smart {
        return Ok(best);
    }
    for candidate in candidates {
        let better = match (candidate.inexact == 0, best.inexact == 0) {
            (true, false) => true,
            (false, true) => false,
            _ => {
                let candidate_fields = field_count(&candidate.value);
                let best_fields = field_count(&best.value);
                candidate_fields > best_fields
                    || (candidate_fields == best_fields && candidate.inexact < best.inexact)
            }
        };
        if better {
            best = candidate;
        }
    }
    Ok(best)
}

fn field_count(value: &Value) -> usize {
    match value {
        Value::Array(values) => values.iter().map(field_count).sum(),
        Value::Object(values) => values.values().map(field_count).sum(),
        _ => 1,
    }
}

fn merge(left: Value, right: Value, path: &str) -> Result<Value, SchemaError> {
    match (left, right) {
        (Value::Object(mut left), Value::Object(right)) => {
            for (key, right) in right {
                let value = match left.remove(&key) {
                    Some(left) => merge(left, right, &format!("{path}.{key}"))?,
                    None => right,
                };
                left.insert(key, value);
            }
            Ok(Value::Object(left))
        }
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => left
            .into_iter()
            .zip(right)
            .enumerate()
            .map(|(index, (left, right))| merge(left, right, &format!("{path}[{index}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        (left, right) if left == right => Ok(left),
        _ => Err(SchemaError::new(path, "compatible intersection values")),
    }
}

fn normalize_untyped(value: Value) -> Value {
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
    serde_json::from_str(ryu_js::Buffer::new().format(value))
        .expect("a finite JavaScript number is valid JSON")
}
