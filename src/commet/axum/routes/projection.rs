use super::super::support;
use axum::response::Response;
use serde_json::Value;

pub(super) fn json_field(value: Value, field: &str) -> Response {
    value
        .get(field)
        .cloned()
        .map_or_else(support::json_undefined, support::json)
}

pub(super) fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

pub(super) fn property_string(value: &Value, property: &str) -> String {
    let value = match value {
        Value::Object(object) => object.get(property),
        _ => None,
    };
    js_string(value)
}

pub(super) fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| match value {
                Value::Null => String::new(),
                value => js_string(Some(value)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_truthy, js_string, property_string};
    use serde_json::json;

    #[test]
    fn json_values_follow_javascript_truthiness() {
        for value in [json!(null), json!(false), json!(0), json!(-0.0), json!("")] {
            assert!(!is_truthy(&value), "{value} should be falsy");
        }
        for value in [json!(true), json!(1), json!("0"), json!([]), json!({})] {
            assert!(is_truthy(&value), "{value} should be truthy");
        }
    }

    #[test]
    fn property_access_and_string_coercion_match_javascript() {
        assert_eq!(property_string(&json!({}), "id"), "undefined");
        assert_eq!(property_string(&json!({"id": null}), "id"), "null");
        assert_eq!(
            property_string(&json!({"id": ["one", null, 3]}), "id"),
            "one,,3"
        );
        assert_eq!(property_string(&json!({"id": {}}), "id"), "[object Object]");
        assert_eq!(js_string(None), "undefined");
    }
}
