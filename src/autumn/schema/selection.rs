use super::{
    SchemaError,
    engine::{Data, Outcome, normalize},
};
use serde_json::Value;

pub(super) fn normalize_union(
    options: &[usize],
    data: Data,
    path: &str,
    depth: usize,
    smart: bool,
) -> Result<Outcome, SchemaError> {
    let attempts = options
        .iter()
        .map(|option| normalize(*option, data.clone(), path, depth + 1))
        .collect::<Vec<_>>();
    let errors = attempts
        .iter()
        .filter_map(|attempt| attempt.as_ref().err().cloned())
        .collect::<Vec<_>>();
    let mut candidates = attempts.into_iter().filter_map(Result::ok);
    let Some(mut best) = candidates.next() else {
        return Err(SchemaError::invalid_union(path, errors));
    };
    if !smart {
        return Ok(best);
    }
    for candidate in candidates {
        if is_better(&candidate, &best) {
            best = candidate;
        }
    }
    Ok(best)
}

fn is_better(candidate: &Outcome, best: &Outcome) -> bool {
    let candidate_fields = field_count(&candidate.data).saturating_sub(candidate.zero_defaults);
    let best_fields = field_count(&best.data).saturating_sub(best.zero_defaults);
    match (candidate.inexact == 0, best.inexact == 0) {
        (true, false) => true,
        (false, true) => false,
        _ => {
            candidate_fields > best_fields
                || (candidate_fields == best_fields && candidate.inexact < best.inexact)
        }
    }
}

fn field_count(data: &Data) -> usize {
    match data {
        Data::Missing => 0,
        Data::Value(Value::Array(values)) => values
            .iter()
            .map(|value| field_count(&Data::Value(value.clone())))
            .sum(),
        Data::Value(Value::Object(values)) => values
            .values()
            .map(|value| field_count(&Data::Value(value.clone())))
            .sum(),
        Data::Value(_) => 1,
    }
}

pub(super) fn merge_data(left: Data, right: Data, path: &str) -> Result<Data, SchemaError> {
    match (left, right) {
        (Data::Missing, Data::Missing) => Ok(Data::Missing),
        (Data::Value(left), Data::Value(right)) => merge(left, right, path).map(Data::Value),
        _ => Err(SchemaError::new(path, "compatible intersection values")),
    }
}

fn merge(left: Value, right: Value, path: &str) -> Result<Value, SchemaError> {
    match (left, right) {
        (Value::Object(mut left), Value::Object(right)) => {
            for (key, right) in right {
                let value = match left.shift_remove(&key) {
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
