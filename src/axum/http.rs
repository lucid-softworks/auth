use crate::{AuthError, AuthService, SessionWithUser, cookie::ResolvedCookie};
use axum::{
    Extension,
    extract::ConnectInfo,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

pub(crate) use super::error::auth_error;

pub(crate) type PeerAddress = Option<Extension<ConnectInfo<SocketAddr>>>;

pub(crate) async fn current_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<SessionWithUser> {
    let token = session_token(service, headers)?;
    service.session(&token).await.ok().flatten()
}

pub(crate) fn challenge_token(
    service: &AuthService,
    headers: &HeaderMap,
    cookie_suffix: &str,
) -> Option<String> {
    let cookie = service.passkey_challenge_cookie(cookie_suffix);
    signed_cookie_token(service, headers, &cookie.name)
}

pub(crate) fn with_challenge_cookie(
    service: &AuthService,
    cookie_suffix: &str,
    token: &str,
    body: impl IntoResponse,
) -> Response {
    let cookie = service.passkey_challenge_cookie(cookie_suffix);
    with_cookie(
        body,
        serialize_cookie(&cookie, &service.signed_cookie_value(token), Some(300)),
    )
}

pub(crate) fn with_session_cookie(
    service: &AuthService,
    token: &str,
    remember_me: Option<bool>,
    body: impl IntoResponse,
) -> Response {
    let cookie = service.session_cookie();
    let max_age = (remember_me != Some(false)).then(|| service.session_ttl().num_seconds());
    with_cookie(
        body,
        serialize_cookie(&cookie, &service.signed_cookie_value(token), max_age),
    )
}

pub(super) fn clear_session_cookie(service: &AuthService, body: impl IntoResponse) -> Response {
    with_cookie(
        body,
        serialize_cookie(&service.session_cookie(), "", Some(0)),
    )
}

pub fn session_token(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    let cookie = service.session_cookie();
    signed_cookie_token(service, headers, &cookie.name)
}

fn signed_cookie_token(service: &AuthService, headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_value = headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|cookie| cookie.strip_prefix(&format!("{name}=")))?;
    service.verify_cookie_value(cookie_value)
}

pub(crate) fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect())
}

pub(crate) fn client_ip(
    service: &AuthService,
    headers: &HeaderMap,
    peer: PeerAddress,
) -> Option<String> {
    service.resolve_client_ip(
        peer.map(|Extension(ConnectInfo(address))| address.ip()),
        |name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        },
    )
}

fn serialize_cookie(cookie: &ResolvedCookie, value: &str, max_age_seconds: Option<i64>) -> String {
    let mut serialized = format!("{}={value}", cookie.name);
    if cookie.attributes.http_only {
        serialized.push_str("; HttpOnly");
    }
    serialized.push_str(&format!(
        "; SameSite={}; Path={}",
        cookie.attributes.same_site.as_str(),
        cookie.attributes.path
    ));
    if let Some(domain) = &cookie.attributes.domain {
        serialized.push_str(&format!("; Domain={domain}"));
    }
    if let Some(max_age) = max_age_seconds {
        serialized.push_str(&format!("; Max-Age={max_age}"));
    }
    if cookie.attributes.secure {
        serialized.push_str("; Secure");
    }
    serialized
}

fn with_cookie(body: impl IntoResponse, cookie: String) -> Response {
    let mut response = body.into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().insert(header::SET_COOKIE, value);
            response
        }
        Err(_) => auth_error(AuthError::InvalidConfiguration(
            "session cookie could not be encoded".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_matches_the_better_auth_cookie_name() {
        let cookie = crate::CookieConfig::default().resolve(
            crate::cookie::CookieKind::SessionToken,
            false,
            None,
        );
        let cookie = serialize_cookie(&cookie, "token.signature", Some(300));
        assert_eq!(
            cookie,
            "better-auth.session_token=token.signature; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"
        );
    }

    #[test]
    fn cookie_expiration_preserves_creation_scope() {
        let mut config = crate::CookieConfig::default();
        config.default_attributes.path = Some("/auth".into());
        config.default_attributes.domain = Some(".example.com".into());
        let cookie = config.resolve(crate::cookie::CookieKind::SessionToken, true, None);
        assert_eq!(
            serialize_cookie(&cookie, "", Some(0)),
            "__Secure-better-auth.session_token=; HttpOnly; SameSite=Lax; Path=/auth; Domain=.example.com; Max-Age=0; Secure"
        );
    }
}
