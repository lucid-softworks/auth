use crate::AuthError;

pub(super) fn is_unique_violation(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::Storage(message) if is_unique_violation_message(message)
    )
}

fn is_unique_violation_message(message: &str) -> bool {
    (message.contains("2601") || message.contains("2627"))
        && (message.contains("duplicate")
            || message.contains("Duplicate")
            || message.contains("UNIQUE"))
}

#[cfg(test)]
mod tests {
    use super::is_unique_violation;
    use crate::AuthError;

    #[test]
    fn classifies_mssql_duplicate_entry_errors_only() {
        assert!(is_unique_violation(&AuthError::Storage(
            "Server error: code 2627, Violation of UNIQUE KEY constraint 'user_email_uidx'"
                .into(),
        )));
        assert!(!is_unique_violation(&AuthError::Storage(
            "Server error: code 547, The INSERT statement conflicted with a FOREIGN KEY".into(),
        )));
        assert!(!is_unique_violation(&AuthError::Storage(
            "UNIQUE constraint failed: user.email".into(),
        )));
    }
}
