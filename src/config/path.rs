use crate::AuthError;

pub(super) fn normalize(value: &str) -> Result<String, AuthError> {
    let value = value.trim();
    if value.is_empty() || value.contains(['?', '#', '\\']) || value.chars().any(char::is_control) {
        return Err(AuthError::InvalidConfiguration(
            "base path must be a non-empty URL path without a query or fragment".into(),
        ));
    }
    let with_slash = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    };
    let normalized = with_slash.trim_end_matches('/');
    Ok(if normalized.is_empty() {
        "/".into()
    } else {
        normalized.into()
    })
}
