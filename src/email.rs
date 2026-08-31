use crate::{AuthError, AuthUser};
use async_trait::async_trait;
use chrono::Duration;
use std::sync::Arc;

/// Secret-bearing payload delivered only to the configured native sender.
#[derive(Clone)]
pub struct VerificationEmail {
    pub user: AuthUser,
    pub url: String,
    pub token: String,
}

#[async_trait]
pub trait VerificationEmailSender: Send + Sync {
    async fn send(&self, email: VerificationEmail) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct PasswordResetEmail {
    pub user: AuthUser,
    pub url: String,
    pub token: String,
}

#[async_trait]
pub trait PasswordResetEmailSender: Send + Sync {
    async fn send(&self, email: PasswordResetEmail) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PasswordResetCallback: Send + Sync {
    async fn on_password_reset(&self, user: AuthUser) -> Result<(), AuthError>;
}

/// Better Auth 1.7.2 email-verification settings.
#[derive(Clone)]
pub struct EmailVerificationConfig {
    pub sender: Option<Arc<dyn VerificationEmailSender>>,
    pub send_on_sign_up: Option<bool>,
    pub send_on_sign_in: bool,
    pub auto_sign_in_after_verification: bool,
    pub expires_in: Duration,
}

impl Default for EmailVerificationConfig {
    fn default() -> Self {
        Self {
            sender: None,
            send_on_sign_up: None,
            send_on_sign_in: false,
            auto_sign_in_after_verification: false,
            expires_in: Duration::hours(1),
        }
    }
}

const PLACEHOLDER_EMAIL_DOMAIN: &str = "placeholder.invalid";

pub(crate) fn placeholder_email(
    identifier: &str,
    namespace: &str,
) -> Result<String, AuthError> {
    let email = format!("{identifier}@{namespace}.{PLACEHOLDER_EMAIL_DOMAIN}");
    valid_address(&email)
        .then_some(email)
        .ok_or(AuthError::InvalidEmail)
}

pub(crate) fn valid_address(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if domain.contains('@')
        || local.starts_with('.')
        || local.contains("..")
        || local.is_empty()
        || !local
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_'+-.".contains(character))
        || !local
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_alphanumeric() || "_+-".contains(character))
    {
        return false;
    }
    let labels: Vec<_> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_alphanumeric())
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        && labels.last().is_some_and(|label| {
            label.len() >= 2
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphabetic())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_emails_are_namespaced_and_non_routable() {
        assert_eq!(
            placeholder_email("account-42", "provider").unwrap(),
            "account-42@provider.placeholder.invalid"
        );
    }

    #[test]
    fn placeholder_emails_reject_invalid_identifiers_and_namespaces() {
        assert!(placeholder_email("bad@identifier", "provider").is_err());
        assert!(placeholder_email("account", "bad_namespace").is_err());
    }
}
