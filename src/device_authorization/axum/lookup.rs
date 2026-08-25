use crate::device_authorization::{DeviceAuthorizationStore, DeviceCode};

const DEFAULT_USER_ALPHABET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub(super) async fn by_user_code(
    store: &dyn DeviceAuthorizationStore,
    user_code: &str,
) -> Result<Option<DeviceCode>, crate::AuthError> {
    if let Some(exact) = store.find_device_code_by_user_code(user_code).await? {
        return Ok(Some(exact));
    }
    let normalized = normalize(user_code);
    if normalized == user_code || !is_default_code(&normalized) {
        return Ok(None);
    }
    store.find_device_code_by_user_code(&normalized).await
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_uppercase)
        .collect()
}

fn is_default_code(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| DEFAULT_USER_ALPHABET.contains(character))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_default_alphabet_candidates() {
        assert_eq!(normalize("ab2c-3def"), "AB2C3DEF");
        assert!(is_default_code("AB2C3DEF"));
        assert!(!is_default_code("AB1C0DEF"));
        assert!(!is_default_code(""));
    }
}
