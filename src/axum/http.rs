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
    if let Some(token) = session_token(service, headers) {
        if let Some(session) = service.session(&token).await.ok().flatten() {
            return Some(session);
        }
        if let Some(cache) = session_data_cookie(service, headers)
            && let Some(session) = service.decode_stateless_session(&token, &cache)
        {
            return Some(session);
        }
    }
    service
        .plugin_session(headers)
        .await
        .ok()
        .flatten()
        .map(|session| session.session)
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

pub(crate) async fn with_session_cookie(
    service: &AuthService,
    token: &str,
    remember_me: Option<bool>,
    body: impl IntoResponse,
) -> Response {
    let cookie = service.session_cookie();
    let max_age = (remember_me != Some(false)).then(|| service.session_ttl().num_seconds());
    let response = with_cookie(
        body,
        serialize_cookie(&cookie, &service.signed_cookie_value(token), max_age),
    );
    let response = if remember_me == Some(false) {
        with_cookie(
            response,
            serialize_cookie(
                &service.dont_remember_cookie(),
                &service.signed_cookie_value("true"),
                None,
            ),
        )
    } else {
        response
    };
    with_session_cache_cookie(service, token, None, remember_me, response).await
}

pub(crate) async fn with_session_cache_cookie(
    service: &AuthService,
    token: &str,
    session: Option<&SessionWithUser>,
    remember_me: Option<bool>,
    body: impl IntoResponse,
) -> Response {
    let response = body.into_response();
    match service.encode_session_cookie_cache(token, session).await {
        Ok(Some(value)) => with_chunked_session_data_cookie(
            service,
            &value,
            (remember_me != Some(false)).then(|| service.cookie_cache_max_age()),
            response,
        ),
        Ok(None) => response,
        Err(error) => auth_error(error),
    }
}

pub(crate) fn clear_session_cookie(service: &AuthService, body: impl IntoResponse) -> Response {
    let response = with_cookie(
        body,
        serialize_cookie(&service.session_cookie(), "", Some(0)),
    );
    let response = with_cookie(
        response,
        serialize_cookie(&service.session_data_cookie(), "", Some(0)),
    );
    with_cookie(
        response,
        serialize_cookie(&service.dont_remember_cookie(), "", Some(0)),
    )
}

pub(crate) fn session_data_cookie(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    let cookie = service.session_data_cookie();
    let values: Vec<_> = headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .filter_map(|value| value.split_once('='))
        .collect();
    if let Some((_, value)) = values.iter().find(|(name, _)| *name == cookie.name) {
        return Some((*value).into());
    }
    let prefix = format!("{}.", cookie.name);
    let mut chunks: Vec<_> = values
        .into_iter()
        .filter_map(|(name, value)| {
            let index = name.strip_prefix(&prefix)?.parse::<usize>().ok()?;
            (index < 100).then_some((index, value))
        })
        .collect();
    chunks.sort_by_key(|(index, _)| *index);
    (!chunks.is_empty()).then(|| chunks.into_iter().map(|(_, value)| value).collect())
}

pub(crate) fn with_chunked_session_data_cookie(
    service: &AuthService,
    value: &str,
    max_age: Option<i64>,
    body: impl IntoResponse,
) -> Response {
    const MAX_COOKIE_SIZE: usize = 4_050;
    const MAX_CHUNKS: usize = 100;
    let cookie = service.session_data_cookie();
    if serialize_cookie(&cookie, value, max_age).len() <= MAX_COOKIE_SIZE {
        return with_cookie(body, serialize_cookie(&cookie, value, max_age));
    }
    let mut largest_name = cookie.clone();
    largest_name.name = format!("{}.{}", largest_name.name, MAX_CHUNKS - 1);
    let overhead = serialize_cookie(&largest_name, "", max_age).len();
    let chunk_size = MAX_COOKIE_SIZE.saturating_sub(overhead);
    let count = value.len().div_ceil(chunk_size.max(1));
    let mut response = body.into_response();
    if chunk_size == 0 || count > MAX_CHUNKS {
        return response;
    }
    for (index, bytes) in value.as_bytes().chunks(chunk_size).enumerate() {
        let mut chunk = cookie.clone();
        chunk.name = format!("{}.{}", chunk.name, index);
        let value = std::str::from_utf8(bytes).expect("cookie cache is base64url ASCII");
        response = with_cookie(response, serialize_cookie(&chunk, value, max_age));
    }
    response
}

pub fn session_token(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    let cookie = service.session_cookie();
    signed_cookie_token(service, headers, &cookie.name)
}

pub(crate) fn dont_remember(service: &AuthService, headers: &HeaderMap) -> bool {
    let cookie = service.dont_remember_cookie();
    signed_cookie_token(service, headers, &cookie.name).as_deref() == Some("true")
}

pub(crate) fn signed_cookie_token(
    service: &AuthService,
    headers: &HeaderMap,
    name: &str,
) -> Option<String> {
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
    _peer: PeerAddress,
) -> Option<String> {
    service.resolve_client_ip(|name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    })
}

pub(crate) fn serialize_cookie(
    cookie: &ResolvedCookie,
    value: &str,
    max_age_seconds: Option<i64>,
) -> String {
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

pub(crate) fn with_cookie(body: impl IntoResponse, cookie: String) -> Response {
    let mut response = body.into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().append(header::SET_COOKIE, value);
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
