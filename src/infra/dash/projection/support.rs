use super::super::tracking::EventLocation;
use crate::{AuthService, DatabaseHookContext};
use serde_json::{Map, Value};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Trigger {
    pub actor: String,
    pub context: &'static str,
}

pub(super) struct ProjectionContext {
    pub path: String,
    pub body: Map<String, Value>,
    pub location: EventLocation,
}

impl ProjectionContext {
    pub(super) fn new(service: &AuthService, context: &DatabaseHookContext) -> Self {
        let path = context
            .request
            .as_ref()
            .map(|request| relative_path(&request.path, service.base_path()))
            .unwrap_or_default();
        Self {
            path,
            body: crate::database_hooks::current_request_body()
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default(),
            location: EventLocation::from_request(context.request.as_ref()),
        }
    }
}

pub(super) async fn trigger(
    service: &AuthService,
    context: &DatabaseHookContext,
    subject_id: &str,
) -> Trigger {
    let actor = request_actor(service, context)
        .await
        .unwrap_or_else(|| subject_id.to_owned());
    let kind = if actor == subject_id {
        "user"
    } else if route(&context_path(service, context), "/admin") {
        "admin"
    } else if route(&context_path(service, context), "/dash") {
        "dashboard"
    } else if actor == "unknown" {
        "user"
    } else {
        "unknown"
    };
    Trigger {
        actor,
        context: kind,
    }
}

#[cfg(feature = "axum")]
async fn request_actor(
    service: &AuthService,
    context: &DatabaseHookContext,
) -> Option<String> {
    let request = context.request.as_ref()?;
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in &request.headers {
        if let (Ok(name), Ok(value)) = (name.parse::<axum::http::HeaderName>(), value.parse()) {
            headers.append(name, value);
        }
    }
    service
        .plugin_session(&headers)
        .await
        .ok()
        .flatten()
        .map(|session| session.session.user.id)
}

#[cfg(not(feature = "axum"))]
async fn request_actor(
    _service: &AuthService,
    _context: &DatabaseHookContext,
) -> Option<String> {
    None
}

fn context_path(service: &AuthService, context: &DatabaseHookContext) -> String {
    context
        .request
        .as_ref()
        .map(|request| relative_path(&request.path, service.base_path()))
        .unwrap_or_default()
}

fn relative_path(path: &str, base_path: &str) -> String {
    let base = base_path.trim_end_matches('/');
    path.strip_prefix(base)
        .filter(|path| path.starts_with('/'))
        .unwrap_or(path)
        .to_owned()
}

pub(super) fn route(path: &str, pattern: &str) -> bool {
    if pattern.contains(':') {
        let prefix = pattern.split(':').next().unwrap_or(pattern);
        return path.starts_with(prefix) && path.len() > prefix.len();
    }
    path == pattern
        || path
            .strip_prefix(pattern)
            .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with('?'))
}

pub(super) fn login_method(path: &str) -> Option<&str> {
    const ROUTES: &[(&str, &str)] = &[
        ("/sign-in/email", "email"),
        ("/sign-up/email", "email"),
        ("/sign-in/username", "username"),
        ("/sign-in/email-otp", "email-otp"),
        ("/sign-in/social", "social"),
        ("/sign-in/anonymous", "anonymous"),
        ("/sign-in/passkey", "passkey"),
        ("/sign-in/magic-link", "magic-link"),
        ("/magic-link/verify", "magic-link"),
        ("/sign-in/sso", "sso"),
        ("/phone-number/verify-phone-number", "phone"),
        ("/two-factor/verify-totp", "totp"),
        ("/two-factor/verify-otp", "two-factor-otp"),
        ("/two-factor/verify-backup-code", "backup-code"),
        ("/admin/impersonate-user", "impersonation"),
        ("/device/token", "device-code"),
        ("/siwe/verify", "siwe"),
    ];
    if let Some(provider) = path.strip_prefix("/callback/").filter(|value| !value.is_empty()) {
        return Some(provider.split('/').next().unwrap_or(provider));
    }
    if let Some(provider) = path
        .strip_prefix("/oauth2/callback/")
        .filter(|value| !value.is_empty())
    {
        return Some(provider.split('/').next().unwrap_or(provider));
    }
    ROUTES
        .iter()
        .find_map(|(pattern, method)| route(path, pattern).then_some(*method))
}

pub(super) fn data(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_and_login_method_match_the_published_prefix_rules() {
        assert!(route("/sign-in/email", "/sign-in"));
        assert!(!route("/sign-injected", "/sign-in"));
        assert_eq!(login_method("/callback/google"), Some("google"));
        assert_eq!(login_method("/two-factor/verify-totp"), Some("totp"));
    }
}
