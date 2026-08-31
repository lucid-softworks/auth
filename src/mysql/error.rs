use crate::AuthError;

pub(super) fn is_unique_violation(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::Storage(message) if is_unique_violation_message(message)
    )
}

fn is_unique_violation_message(message: &str) -> bool {
    message.contains("1062") && message.contains("Duplicate entry")
}

#[cfg(test)]
mod tests {
    use super::is_unique_violation;
    use crate::AuthError;

    #[test]
    fn classifies_mysql_duplicate_entry_errors_only() {
        assert!(is_unique_violation(&AuthError::Storage(
            "error returned from database: 1062 (23000): Duplicate entry 'x' for key 'user.email'"
                .into(),
        )));
        assert!(!is_unique_violation(&AuthError::Storage(
            "error returned from database: 1452 (23000): Cannot add or update a child row".into(),
        )));
        assert!(!is_unique_violation(&AuthError::Storage(
            "UNIQUE constraint failed: user.email".into(),
        )));
    }
}
