use super::{LastLoginMethodContext, LastLoginMethodPlugin, context::resolve_method};
use crate::{AuthError, AuthService, PluginRequestContext, cookie::encode_cookie_component};
use ::axum::{
    http::{HeaderValue, header},
    response::Response,
};

const MAX_COOKIE_AGE: f64 = 34_560_000.0;

pub(super) async fn after_response(
    plugin: &LastLoginMethodPlugin,
    service: &AuthService,
    request: &PluginRequestContext,
    mut response: Response,
) -> Response {
    let context = LastLoginMethodContext::from_plugin_request(request);
    let method = match resolve_method(plugin.config.custom_resolve_method.as_deref(), &context) {
        Ok(Some(method)) if !method.is_empty() => method,
        Ok(_) => return response,
        Err(error) => return crate::axum::http::auth_error(error),
    };
    let session_cookie_name = service.session_cookie().name;
    let has_session_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|cookie| cookie.contains(&session_cookie_name));
    if !has_session_cookie {
        return response;
    }
    if let Some(policy) = &plugin.config.before_store_cookie {
        match policy.permit(context, method.clone()).await {
            Ok(true) => {}
            Ok(false) => return response,
            Err(error) => {
                eprintln!("[LastLoginMethod] Error in beforeStoreCookie hook: {error}");
                return response;
            }
        }
    }
    let cookie = match serialize_cookie(plugin, service, &method) {
        Ok(cookie) => cookie,
        Err(error) => return crate::axum::http::auth_error(error),
    };
    let value = match HeaderValue::from_str(&cookie) {
        Ok(value) => value,
        Err(_) => {
            return crate::axum::http::auth_error(AuthError::InvalidConfiguration(
                "last-login-method cookie could not be encoded".into(),
            ));
        }
    };
    response.headers_mut().append(header::SET_COOKIE, value);
    response
}

fn serialize_cookie(
    plugin: &LastLoginMethodPlugin,
    service: &AuthService,
    method: &str,
) -> Result<String, AuthError> {
    let mut attributes = service.session_cookie().attributes;
    attributes.http_only = false;
    let name = &plugin.config.cookie_name;
    if name.starts_with("__Secure-") {
        attributes.secure = true;
    }
    if name.starts_with("__Host-") {
        attributes.secure = true;
        attributes.path = "/".into();
        attributes.domain = None;
    }
    let mut cookie = format!("{name}={}", encode_cookie_component(method));
    let max_age = plugin.config.max_age;
    if max_age >= 0.0 {
        if max_age > MAX_COOKIE_AGE {
            return Err(AuthError::InvalidConfiguration(
                "Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration."
                    .into(),
            ));
        }
        cookie.push_str(&format!("; Max-Age={}", max_age.floor() as i64));
    }
    if let Some(domain) = &attributes.domain {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    if !attributes.path.is_empty() {
        cookie.push_str(&format!("; Path={}", attributes.path));
    }
    if attributes.secure {
        cookie.push_str("; Secure");
    }
    cookie.push_str(&format!("; SameSite={}", attributes.same_site.as_str()));
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore, SameSite};
    use std::sync::Arc;

    #[test]
    fn cookie_serialization_matches_better_call() {
        let plugin = LastLoginMethodPlugin::default();
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([151_u8; 32]).unwrap(),
        );
        assert_eq!(
            serialize_cookie(&plugin, &service, "oidc/google +foo").unwrap(),
            "better-auth.last_used_login_method=oidc%2Fgoogle%20%2Bfoo; Max-Age=2592000; Path=/; SameSite=Lax"
        );
    }

    #[test]
    fn inherited_attributes_and_host_prefix_follow_better_call() {
        let mut auth = AuthConfig::new([152_u8; 32]).unwrap();
        auth.cookies.default_attributes.domain = Some(".example.com".into());
        auth.cookies.default_attributes.path = Some("/auth".into());
        auth.cookies.default_attributes.same_site = Some(SameSite::None);
        let service = AuthService::new(Arc::new(MemoryStore::default()), auth);
        let config = super::super::LastLoginMethodConfig {
            cookie_name: "__Host-last-login".into(),
            max_age: 1.9,
            ..super::super::LastLoginMethodConfig::default()
        };
        let plugin = LastLoginMethodPlugin::new(config);
        assert_eq!(
            serialize_cookie(&plugin, &service, "email").unwrap(),
            "__Host-last-login=email; Max-Age=1; Path=/; Secure; SameSite=None"
        );
    }

    #[test]
    fn max_age_omission_and_limit_match_better_call() {
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([153_u8; 32]).unwrap(),
        );
        for max_age in [-1.0, f64::NAN] {
            let config = super::super::LastLoginMethodConfig {
                max_age,
                ..super::super::LastLoginMethodConfig::default()
            };
            let cookie =
                serialize_cookie(&LastLoginMethodPlugin::new(config), &service, "email").unwrap();
            assert_eq!(
                cookie,
                "better-auth.last_used_login_method=email; Path=/; SameSite=Lax"
            );
        }
        let config = super::super::LastLoginMethodConfig {
            max_age: f64::INFINITY,
            ..super::super::LastLoginMethodConfig::default()
        };
        assert!(serialize_cookie(&LastLoginMethodPlugin::new(config), &service, "email").is_err());
    }
}
