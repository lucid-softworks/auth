use crate::{
    AgentCapabilityConstraints, AgentConstraintOperators, AgentConstraintPrimitive,
    AgentConstraintValue,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ConstraintViolation {
    field: String,
    constraint: Value,
    actual: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConstraintValidation {
    pub valid: bool,
    pub violations: Vec<ConstraintViolation>,
    pub unknown_operators: Vec<String>,
}

pub(crate) fn validate_constraints(
    constraints: &AgentCapabilityConstraints,
    arguments: Option<&Map<String, Value>>,
) -> ConstraintValidation {
    let empty = Map::new();
    let arguments = arguments.unwrap_or(&empty);
    let mut result = ConstraintValidation {
        valid: true,
        violations: Vec::new(),
        unknown_operators: Vec::new(),
    };
    for (field, constraint) in constraints {
        check_field(
            field,
            constraint,
            arguments.get(field).cloned().unwrap_or(Value::Null),
            &mut result,
        );
    }
    result.valid = result.violations.is_empty() && result.unknown_operators.is_empty();
    result
}

fn check_field(
    field: &str,
    constraint: &AgentConstraintValue,
    actual: Value,
    result: &mut ConstraintValidation,
) {
    match constraint {
        AgentConstraintValue::Primitive(expected) => {
            if !primitive_equals_value(expected, &actual) {
                violation(result, field, json!({"eq": expected}), actual);
            }
        }
        AgentConstraintValue::Operators(operators) => {
            result
                .unknown_operators
                .extend(operators.unknown.keys().cloned());
            check_operators(field, operators, actual, result);
        }
    }
}

fn check_operators(
    field: &str,
    operators: &AgentConstraintOperators,
    actual: Value,
    result: &mut ConstraintValidation,
) {
    if let Some(expected) = &operators.eq
        && !primitive_equals_value(expected, &actual)
    {
        violation(result, field, json!({"eq": expected}), actual.clone());
    }
    if let Some(minimum) = operators.min
        && actual.as_f64().is_none_or(|actual| actual < minimum)
    {
        violation(result, field, json!({"min": minimum}), actual.clone());
    }
    if let Some(maximum) = operators.max
        && actual.as_f64().is_none_or(|actual| actual > maximum)
    {
        violation(result, field, json!({"max": maximum}), actual.clone());
    }
    if let Some(allowed) = &operators.r#in
        && !allowed
            .iter()
            .any(|expected| primitive_equals_value(expected, &actual))
    {
        violation(result, field, json!({"in": allowed}), actual.clone());
    }
    if let Some(denied) = &operators.not_in
        && denied
            .iter()
            .any(|expected| primitive_equals_value(expected, &actual))
    {
        violation(result, field, json!({"not_in": denied}), actual);
    }
}

fn violation(result: &mut ConstraintValidation, field: &str, constraint: Value, actual: Value) {
    result.violations.push(ConstraintViolation {
        field: field.to_owned(),
        constraint,
        actual,
    });
}

fn primitive_equals_value(expected: &AgentConstraintPrimitive, actual: &Value) -> bool {
    match expected {
        AgentConstraintPrimitive::String(expected) => actual.as_str() == Some(expected),
        AgentConstraintPrimitive::Number(expected) => actual.as_f64() == Some(*expected),
        AgentConstraintPrimitive::Boolean(expected) => actual.as_bool() == Some(*expected),
    }
}

#[cfg(feature = "axum")]
pub(crate) fn constraints_cover(
    existing: Option<&AgentCapabilityConstraints>,
    requested: Option<&AgentCapabilityConstraints>,
) -> bool {
    let Some(existing) = existing else {
        return true;
    };
    let Some(requested) = requested else {
        return false;
    };
    requested.iter().all(|(field, requested)| {
        existing
            .get(field)
            .is_none_or(|existing| field_constraint_covers(existing, requested))
    })
}

#[cfg(feature = "axum")]
fn field_constraint_covers(
    existing: &AgentConstraintValue,
    requested: &AgentConstraintValue,
) -> bool {
    let existing_ops = normalized(existing);
    let requested_ops = normalized(requested);
    if let Some(existing_eq) = existing_ops.eq.as_ref() {
        if let Some(requested_eq) = requested_ops.eq.as_ref() {
            return existing_eq == requested_eq;
        }
        if let Some(requested_in) = requested_ops.r#in.as_ref() {
            return requested_in.as_slice() == [existing_eq.clone()];
        }
        return false;
    }
    if let Some(existing_in) = existing_ops.r#in.as_ref() {
        if let Some(requested_eq) = requested_ops.eq.as_ref() {
            return existing_in
                .iter()
                .any(|value| string_equal(value, requested_eq));
        }
        if let Some(requested_in) = requested_ops.r#in.as_ref() {
            return requested_in
                .iter()
                .all(|value| existing_in.iter().any(|item| string_equal(item, value)));
        }
        return false;
    }
    if (existing_ops.min.is_some() || existing_ops.max.is_some())
        && (requested_ops
            .min
            .zip(existing_ops.min)
            .is_some_and(|(r, e)| r < e)
            || requested_ops
                .max
                .zip(existing_ops.max)
                .is_some_and(|(r, e)| r > e))
    {
        return false;
    }
    serde_json::to_value(existing).ok() == serde_json::to_value(requested).ok()
}

#[cfg(feature = "axum")]
fn normalized(value: &AgentConstraintValue) -> AgentConstraintOperators {
    match value {
        AgentConstraintValue::Primitive(value) => AgentConstraintOperators {
            eq: Some(value.clone()),
            ..AgentConstraintOperators::default()
        },
        AgentConstraintValue::Operators(operators) => operators.clone(),
    }
}

#[cfg(feature = "axum")]
fn string_equal(left: &AgentConstraintPrimitive, right: &AgentConstraintPrimitive) -> bool {
    primitive_string(left) == primitive_string(right)
}

#[cfg(feature = "axum")]
fn primitive_string(value: &AgentConstraintPrimitive) -> String {
    match value {
        AgentConstraintPrimitive::String(value) => value.clone(),
        AgentConstraintPrimitive::Number(value) => value.to_string(),
        AgentConstraintPrimitive::Boolean(value) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn validates_every_official_operator_and_reports_unknown_ones() {
        let constraints = BTreeMap::from([
            (
                "amount".into(),
                AgentConstraintValue::Operators(AgentConstraintOperators {
                    min: Some(10.0),
                    max: Some(20.0),
                    ..AgentConstraintOperators::default()
                }),
            ),
            (
                "currency".into(),
                AgentConstraintValue::Operators(AgentConstraintOperators {
                    r#in: Some(vec![AgentConstraintPrimitive::String("GBP".into())]),
                    unknown: BTreeMap::from([("matches".into(), json!("G.*"))]),
                    ..AgentConstraintOperators::default()
                }),
            ),
        ]);
        let arguments = Map::from_iter([
            ("amount".into(), json!(25)),
            ("currency".into(), json!("GBP")),
        ]);
        let result = validate_constraints(&constraints, Some(&arguments));
        assert!(!result.valid);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.unknown_operators, ["matches"]);
    }
}
