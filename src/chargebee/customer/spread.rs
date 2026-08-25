use serde_json::{Map, Value};

/// JavaScript object-spread projection used by the published adapter.
pub(crate) fn merge_object_spread(target: &mut Map<String, Value>, value: Value) {
    match value {
        Value::Object(fields) => target.extend(fields),
        Value::Array(values) => {
            target.extend(
                values
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| (index.to_string(), value)),
            );
        }
        Value::String(value) => {
            target.extend(
                value
                    .chars()
                    .enumerate()
                    .map(|(index, character)| (index.to_string(), Value::String(character.into()))),
            );
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(feature = "axum")]
pub(crate) fn metadata_customer_type(metadata: Option<&Value>) -> Option<&str> {
    metadata
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("customerType"))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_spread_matches_arrays_strings_and_nullish_values() {
        let mut output = Map::new();
        merge_object_spread(&mut output, json!(["a", "b"]));
        merge_object_spread(&mut output, json!("xy"));
        merge_object_spread(&mut output, Value::Null);
        assert_eq!(
            output,
            json!({"0": "x", "1": "y"}).as_object().unwrap().clone()
        );
    }
}
