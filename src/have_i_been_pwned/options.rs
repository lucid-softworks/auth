use super::DEFAULT_PASSWORD_COMPROMISED_MESSAGE;

pub const DEFAULT_PATHS: &[&str] = &[
    "/sign-up/email",
    "/change-password",
    "/reset-password",
    "/email-otp/reset-password",
    "/phone-number/reset-password",
    "/admin/create-user",
    "/admin/set-user-password",
];

/// Better Auth 1.7.2 `HaveIBeenPwnedOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HaveIBeenPwnedOptions {
    /// Checks are disabled only when explicitly set to `Some(false)`.
    pub enabled: Option<bool>,
    /// An explicitly supplied list replaces the defaults, including when empty.
    pub paths: Option<Vec<String>>,
    /// Empty values fall back to the official message; whitespace is preserved.
    pub custom_password_compromised_message: Option<String>,
}

impl HaveIBeenPwnedOptions {
    pub fn paths(&self) -> Vec<&str> {
        self.paths
            .as_ref()
            .map(|paths| paths.iter().map(String::as_str).collect())
            .unwrap_or_else(|| DEFAULT_PATHS.to_vec())
    }

    pub fn compromised_message(&self) -> &str {
        self.custom_password_compromised_message
            .as_deref()
            .filter(|message| !message.is_empty())
            .unwrap_or(DEFAULT_PASSWORD_COMPROMISED_MESSAGE)
    }

    pub(crate) fn checks_path(&self, path: &str) -> bool {
        self.paths.as_ref().map_or_else(
            || DEFAULT_PATHS.contains(&path),
            |paths| paths.iter().any(|candidate| candidate.as_str() == path),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_replacement_and_message_truthiness_match_172() {
        let defaults = HaveIBeenPwnedOptions::default();
        assert_eq!(defaults.paths(), DEFAULT_PATHS);
        assert_eq!(
            defaults.compromised_message(),
            DEFAULT_PASSWORD_COMPROMISED_MESSAGE
        );

        let options = HaveIBeenPwnedOptions {
            enabled: Some(false),
            paths: Some(Vec::new()),
            custom_password_compromised_message: Some(String::new()),
        };
        assert!(options.paths().is_empty());
        assert_eq!(
            options.compromised_message(),
            DEFAULT_PASSWORD_COMPROMISED_MESSAGE
        );

        let whitespace = HaveIBeenPwnedOptions {
            custom_password_compromised_message: Some("   ".into()),
            ..HaveIBeenPwnedOptions::default()
        };
        assert_eq!(whitespace.compromised_message(), "   ");
    }
}
