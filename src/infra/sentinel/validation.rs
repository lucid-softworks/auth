use super::SecurityOptions;

const GMAIL_LIKE_DOMAINS: &[&str] = &["gmail.com", "googlemail.com"];
const PLUS_ADDRESSING_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "protonmail.com",
    "proton.me",
    "fastmail.com",
    "zoho.com",
];

/// Resolve the artifact's subtle normalization default and precedence.
pub fn email_normalization_enabled(security: &SecurityOptions) -> bool {
    if let Some(options) = security.email_normalization {
        return options.enabled != Some(false);
    }
    security
        .email_validation
        .as_ref()
        .and_then(|options| options.enabled)
        != Some(false)
}

/// Normalize one email exactly as Sentinel 0.4.3 does before persistence.
pub fn normalize_email(email: &str, security: &SecurityOptions) -> String {
    if email.is_empty() || !email_normalization_enabled(security) {
        return email.to_owned();
    }
    let trimmed = email.trim().to_lowercase();
    let Some(at_index) = trimmed.rfind('@') else {
        return trimmed;
    };
    let mut local_part = trimmed[..at_index].to_owned();
    let mut domain = trimmed[at_index + 1..].to_owned();
    if domain == "googlemail.com" {
        domain = "gmail.com".into();
    }
    if PLUS_ADDRESSING_DOMAINS.contains(&domain.as_str())
        && let Some(plus_index) = local_part.find('+')
    {
        local_part.truncate(plus_index);
    }
    if GMAIL_LIKE_DOMAINS.contains(&domain.as_str()) {
        local_part.retain(|character| character != '.');
    }
    format!("{local_part}@{domain}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::sentinel::{EmailNormalizationOptions, EmailValidationOptions};

    #[test]
    fn explicit_normalization_wins_over_legacy_validation() {
        let security = SecurityOptions {
            email_normalization: Some(EmailNormalizationOptions {
                enabled: Some(false),
            }),
            email_validation: Some(EmailValidationOptions {
                enabled: Some(true),
                strictness: None,
                action: None,
                domain_allowlist: None,
            }),
            ..SecurityOptions::default()
        };
        assert!(!email_normalization_enabled(&security));
        assert_eq!(
            normalize_email(" User.Name+tag@GoogleMail.com ", &security),
            " User.Name+tag@GoogleMail.com "
        );
    }

    #[test]
    fn defaults_to_enabled_unless_legacy_validation_is_disabled() {
        assert!(email_normalization_enabled(&SecurityOptions::default()));
        let security = SecurityOptions {
            email_validation: Some(EmailValidationOptions {
                enabled: Some(false),
                strictness: None,
                action: None,
                domain_allowlist: None,
            }),
            ..SecurityOptions::default()
        };
        assert!(!email_normalization_enabled(&security));
    }

    #[test]
    fn applies_only_the_published_provider_rewrites() {
        let security = SecurityOptions::default();
        assert_eq!(
            normalize_email(" User.Name+tag@GoogleMail.com ", &security),
            "username@gmail.com"
        );
        assert_eq!(
            normalize_email("User.Name+tag@outlook.com", &security),
            "user.name@outlook.com"
        );
        assert_eq!(
            normalize_email("User.Name+tag@example.com", &security),
            "user.name+tag@example.com"
        );
        assert_eq!(normalize_email("  NO-AT  ", &security), "no-at");
    }
}
