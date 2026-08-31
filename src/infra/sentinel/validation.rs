use super::{EmailStrictness, SecurityAction, SecurityOptions, SentinelSecurityClient};
use crate::infra::dash::DashRequest;
use serde_json::{Value, json};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailValidationResult {
    pub valid: bool,
    pub message: Option<&'static str>,
}

impl EmailValidationResult {
    fn allow() -> Self {
        Self {
            valid: true,
            message: None,
        }
    }
}

pub fn email_validation_enabled(security: &SecurityOptions) -> bool {
    security
        .email_validation
        .as_ref()
        .and_then(|options| options.enabled)
        != Some(false)
}

pub fn is_valid_email_format_local(email: &str) -> bool {
    if email.len() > 254 || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
}

impl SentinelSecurityClient {
    pub fn has_api_key(&self) -> bool {
        !self.connection.api_key().is_empty()
    }

    pub async fn validate_email(&self, email: &str) -> EmailValidationResult {
        if !self.has_api_key() {
            return EmailValidationResult::allow();
        }
        let policy = self.fetch_email_policy().await;
        let Some(policy) = policy else {
            return EmailValidationResult::allow();
        };
        if !policy.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
            return EmailValidationResult::allow();
        }
        let result = self.validate_email_remotely(email, &policy).await;
        let Some(result) = result else {
            return EmailValidationResult::allow();
        };
        if email_domain_allowed(email, &policy)
            || result.get("valid").and_then(Value::as_bool).unwrap_or(false)
            || policy.get("action").and_then(Value::as_str) == Some("allow")
        {
            return EmailValidationResult::allow();
        }
        EmailValidationResult {
            valid: false,
            message: Some(email_block_message(&result)),
        }
    }

    async fn fetch_email_policy(&self) -> Option<Value> {
        let configured = self.security.email_validation.as_ref();
        self.post(
            "/security/resolve-policy",
            json!({
                "policyId": "email_validity",
                "config": { "emailValidation": {
                    "enabled": configured.and_then(|options| options.enabled).unwrap_or(true),
                    "strictness": configured.and_then(|options| options.strictness)
                        .unwrap_or(EmailStrictness::Medium),
                    "action": configured.and_then(|options| options.action)
                        .unwrap_or(SecurityAction::Block),
                    "domainAllowlist": configured
                        .and_then(|options| options.domain_allowlist.clone()),
                } }
            }),
        )
        .await
        .and_then(|value| value.get("policy").cloned())
    }

    async fn validate_email_remotely(&self, email: &str, policy: &Value) -> Option<Value> {
        self.kv
            .execute(DashRequest::post(
                "/email/validate",
                json!({
                    "email": email.trim(),
                    "strictness": policy.get("strictness"),
                }),
            ))
            .await
            .ok()
            .and_then(|response| response.data)
    }
}

fn email_domain_allowed(email: &str, policy: &Value) -> bool {
    let domain = email.rsplit_once('@').map(|(_, domain)| domain.to_lowercase());
    matches!(
        (domain.as_deref(), policy.get("domainAllowlist").and_then(Value::as_array)),
        (Some(domain), Some(allowed)) if allowed.iter().any(|value| value.as_str() == Some(domain))
    )
}

fn email_block_message(result: &Value) -> &'static str {
    let reason = result.get("reason").and_then(Value::as_str).unwrap_or("");
    if result
        .get("disposable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || reason == "blocklist"
        || reason.starts_with("known_disposable")
    {
        "Disposable email addresses are not allowed"
    } else if reason == "no_mx_records" {
        "This email domain cannot receive emails"
    } else {
        "This email address appears to be invalid"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::sentinel::{EmailNormalizationOptions, EmailValidationOptions};

    #[cfg(feature = "axum")]
    use crate::infra::dash::InfraConnectionOptions;
    #[cfg(feature = "axum")]
    use axum::{
        Json, Router,
        extract::State,
        http::Uri,
        response::IntoResponse,
        routing::post,
    };
    #[cfg(feature = "axum")]
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "axum")]
    type RecordedCalls = Arc<Mutex<Vec<(String, Value)>>>;

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

    #[test]
    fn validates_the_exact_local_syntax_limits() {
        assert!(is_valid_email_format_local("person@example.com"));
        assert!(!is_valid_email_format_local("person@example"));
        assert!(!is_valid_email_format_local("person @example.com"));
        assert!(!is_valid_email_format_local("person@.example"));
        assert!(!is_valid_email_format_local("person@example."));
        assert!(!is_valid_email_format_local(&format!(
            "{}@example.com",
            "a".repeat(65)
        )));
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn resolves_policy_then_maps_remote_disposable_result() {
        async fn handler(
            State(calls): State<RecordedCalls>,
            uri: Uri,
            Json(body): Json<Value>,
        ) -> impl IntoResponse {
            calls
                .lock()
                .unwrap()
                .push((uri.path().to_owned(), body));
            if uri.path() == "/security/resolve-policy" {
                Json(json!({ "policy": {
                    "enabled": true,
                    "strictness": "high",
                    "action": "block",
                    "domainAllowlist": []
                } }))
            } else {
                Json(json!({
                    "valid": false,
                    "disposable": true,
                    "reason": "known_disposable_domain"
                }))
            }
        }

        let calls = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*path}", post(handler))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let origin = format!("http://{address}");
        let client = SentinelSecurityClient::new(
            InfraConnectionOptions {
                api_url: Some(origin.clone()),
                kv_url: Some(origin),
                api_key: Some("key".into()),
                ..InfraConnectionOptions::default()
            },
            SecurityOptions::default(),
        );

        let result = client.validate_email(" disposable@example.com ").await;
        assert_eq!(
            result.message,
            Some("Disposable email addresses are not allowed")
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls[0].0, "/security/resolve-policy");
        assert_eq!(calls[0].1["config"]["emailValidation"]["strictness"], "medium");
        assert_eq!(calls[1].0, "/email/validate");
        assert_eq!(calls[1].1["email"], "disposable@example.com");
        assert_eq!(calls[1].1["strictness"], "high");
    }
}
