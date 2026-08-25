use serde_json::Value;
use std::collections::BTreeMap;

pub type StripeMetadata = BTreeMap<String, Value>;

const UNSAFE_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// Merge user metadata in order, then overwrite it with protected plugin fields.
pub fn merge_metadata<'a>(
    user_metadata: impl IntoIterator<Item = &'a StripeMetadata>,
    internal_fields: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> StripeMetadata {
    let mut merged = StripeMetadata::new();
    for source in user_metadata {
        for (key, value) in source {
            if !UNSAFE_KEYS.contains(&key.as_str()) {
                merged.insert(key.clone(), value.clone());
            }
        }
    }
    for (key, value) in internal_fields {
        merged.insert(key.to_owned(), Value::String(value.to_owned()));
    }
    merged
}

pub fn escape_search_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_metadata_wins_and_prototype_keys_are_dropped() {
        let user = StripeMetadata::from([
            ("userId".into(), Value::String("attacker".into())),
            ("__proto__".into(), Value::String("polluted".into())),
            ("label".into(), Value::String("kept".into())),
        ]);
        let merged = merge_metadata([&user], [("userId", "real")]);
        assert_eq!(merged.get("userId").and_then(Value::as_str), Some("real"));
        assert_eq!(merged.get("label").and_then(Value::as_str), Some("kept"));
        assert!(!merged.contains_key("__proto__"));
    }

    #[test]
    fn search_escaping_matches_stripe_query_string_rules() {
        assert_eq!(escape_search_value(r#"a\"b"#), r#"a\\\"b"#);
    }
}
