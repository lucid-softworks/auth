use crate::{AuthError, DatabaseHookRequest};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LastLoginMethodContext {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub params: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}

pub trait LastLoginMethodResolver: Send + Sync {
    fn resolve(&self, context: &LastLoginMethodContext) -> Result<Option<String>, AuthError>;
}

impl<F> LastLoginMethodResolver for F
where
    F: Fn(&LastLoginMethodContext) -> Result<Option<String>, AuthError> + Send + Sync,
{
    fn resolve(&self, context: &LastLoginMethodContext) -> Result<Option<String>, AuthError> {
        self(context)
    }
}

impl LastLoginMethodContext {
    pub(super) fn from_database_request(request: &DatabaseHookRequest) -> Self {
        Self::new(
            request.method.clone(),
            request.path.clone(),
            request.query.clone(),
            request.headers.clone(),
        )
    }

    #[cfg(feature = "axum")]
    pub(super) fn from_plugin_request(request: &crate::PluginRequestContext) -> Self {
        Self::new(
            request.method.clone(),
            request.path.clone(),
            request.query.clone(),
            request.headers.clone(),
        )
    }

    fn new(
        method: String,
        path: String,
        query: Option<String>,
        headers: BTreeMap<String, String>,
    ) -> Self {
        let params = callback_id(&path)
            .map(|id| BTreeMap::from([("id".into(), id.into())]))
            .unwrap_or_default();
        Self {
            method,
            path,
            query,
            params,
            headers,
        }
    }
}

pub(super) fn resolve_method(
    resolver: Option<&dyn LastLoginMethodResolver>,
    context: &LastLoginMethodContext,
) -> Result<Option<String>, AuthError> {
    if let Some(method) = resolver
        .map(|resolver| resolver.resolve(context))
        .transpose()?
        .flatten()
    {
        return Ok(Some(method));
    }
    Ok(default_resolve_method(context))
}

fn default_resolve_method(context: &LastLoginMethodContext) -> Option<String> {
    let path = context.path.as_str();
    if path.is_empty() {
        return None;
    }
    if path.starts_with("/callback/") {
        return context
            .params
            .get("id")
            .cloned()
            .or_else(|| path.rsplit('/').next().map(str::to_owned));
    }
    if path == "/sign-in/email" || path == "/sign-up/email" {
        return Some("email".into());
    }
    if path.contains("siwe") {
        return Some("siwe".into());
    }
    if path.contains("/passkey/verify-authentication") {
        return Some("passkey".into());
    }
    if path.starts_with("/magic-link/verify") {
        return Some("magic-link".into());
    }
    None
}

fn callback_id(path: &str) -> Option<&str> {
    path.starts_with("/callback/")
        .then(|| path.rsplit('/').next())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(path: &str) -> LastLoginMethodContext {
        LastLoginMethodContext::new("POST".into(), path.into(), None, BTreeMap::new())
    }

    #[test]
    fn default_resolution_matches_better_auth_order_and_exact_paths() {
        let cases = [
            ("", None),
            ("/callback/Google", Some("Google")),
            ("/callback/siwe", Some("siwe")),
            ("/sign-in/email", Some("email")),
            ("/sign-up/email", Some("email")),
            ("/sign-in/email/", None),
            ("/anything-siwe-here", Some("siwe")),
            ("/passkey/verify-authentication", Some("passkey")),
            ("/magic-link/verify", Some("magic-link")),
            ("/magic-link/verify/token", Some("magic-link")),
            ("/sign-in/username", None),
            ("/sign-in/phone-number", None),
        ];
        for (path, expected) in cases {
            assert_eq!(
                default_resolve_method(&context(path)).as_deref(),
                expected,
                "path {path}"
            );
        }
    }

    #[test]
    fn custom_none_falls_back_while_empty_string_suppresses_the_default() {
        let none = |_context: &LastLoginMethodContext| Ok(None);
        let empty = |_context: &LastLoginMethodContext| Ok(Some(String::new()));
        assert_eq!(
            resolve_method(Some(&none), &context("/sign-in/email"))
                .unwrap()
                .as_deref(),
            Some("email")
        );
        assert_eq!(
            resolve_method(Some(&empty), &context("/sign-in/email")).unwrap(),
            Some(String::new())
        );
    }
}
