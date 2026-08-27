pub(crate) fn normalized_config_id(config_id: &str) -> &str {
    if config_id.is_empty() {
        "default"
    } else {
        config_id
    }
}

pub(crate) fn config_ids_match(left: &str, right: &str) -> bool {
    normalized_config_id(left) == normalized_config_id(right)
}
