const HASH_PREFIX: &str = "api-key:";
const ID_PREFIX: &str = "api-key:by-id:";
const REFERENCE_PREFIX: &str = "api-key:by-ref:";

pub(super) fn by_hash(hash: &str) -> String {
    format!("{HASH_PREFIX}{hash}")
}

pub(super) fn by_id(id: &str) -> String {
    format!("{ID_PREFIX}{id}")
}

pub(super) fn by_reference(reference_id: &str) -> String {
    format!("{REFERENCE_PREFIX}{reference_id}")
}

pub(super) fn parse_reference_ids(value: Option<&str>) -> Vec<String> {
    value
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .unwrap_or_default()
}

pub(super) fn serialize_reference_ids(ids: &[String]) -> String {
    serde_json::to_string(ids).expect("serializing strings cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_better_auth_storage_keys() {
        assert_eq!(by_hash("digest"), "api-key:digest");
        assert_eq!(by_id("key-id"), "api-key:by-id:key-id");
        assert_eq!(by_reference("user-id"), "api-key:by-ref:user-id");
    }

    #[test]
    fn treats_invalid_reference_lists_as_empty() {
        assert_eq!(parse_reference_ids(None), Vec::<String>::new());
        assert_eq!(parse_reference_ids(Some("not-json")), Vec::<String>::new());
        assert_eq!(parse_reference_ids(Some("{}")), Vec::<String>::new());
        assert_eq!(
            parse_reference_ids(Some(r#"["first","second"]"#)),
            vec!["first", "second"]
        );
    }
}
