use crate::{AuthService, service::decode_cookie_component};
use axum::{
    http::{HeaderValue, header},
    response::Response,
};

struct SessionCookie {
    value: String,
    max_age_zero: bool,
}

pub(super) fn expose_session_cookie(service: &AuthService, mut response: Response) -> Response {
    let cookie_name = service.session_cookie().name;
    let session_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| parse_set_cookie(value, &cookie_name))
        .next_back();
    let Some(session_cookie) = session_cookie else {
        return response;
    };
    if session_cookie.value.is_empty() || session_cookie.max_age_zero {
        return response;
    }
    let token = decode_cookie_component(&session_cookie.value);
    let Ok(token) = HeaderValue::from_str(&token) else {
        return response;
    };
    response
        .headers_mut()
        .insert(axum::http::HeaderName::from_static("set-auth-token"), token);
    expose_header(response)
}

fn expose_header(mut response: Response) -> Response {
    let existing = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut names = existing
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !names.iter().any(|name| name == "set-auth-token") {
        names.push("set-auth-token".into());
    }
    if let Ok(value) = HeaderValue::from_str(&names.join(", ")) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, value);
    }
    response
}

fn parse_set_cookie(value: &str, expected_name: &str) -> Option<SessionCookie> {
    let mut parts = value.split(';');
    let (name, value) = parts.next()?.trim().split_once('=')?;
    if name != expected_name {
        return None;
    }
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_owned();
    let max_age_zero = parts
        .filter_map(|part| part.trim().split_once('='))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("max-age") && value.trim().parse() == Ok(0_i64)
        });
    Some(SessionCookie {
        value,
        max_age_zero,
    })
}
