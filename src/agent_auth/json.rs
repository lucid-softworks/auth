use serde_json::Value;

pub(crate) fn javascript_stringify(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value
            .as_f64()
            .map(|value| ryu_js::Buffer::new().format(value).to_owned())
            .unwrap_or_else(|| "null".into()),
        Value::String(value) => serde_json::to_string(value).expect("a JSON string serializes"),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(javascript_stringify)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    serde_json::to_string(key).expect("a JSON key serializes"),
                    javascript_stringify(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_json_stringify_for_spacing_order_and_numbers() {
        let value: Value =
            serde_json::from_str(r#" { "first": 1.0, "nested": [true, null, 9007199254740993] } "#)
                .unwrap();
        assert_eq!(
            javascript_stringify(&value),
            r#"{"first":1,"nested":[true,null,9007199254740992]}"#
        );
    }
}
