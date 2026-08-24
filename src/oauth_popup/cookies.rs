use crate::{AuthError, cookie::ResolvedCookie, service::decode_cookie_component};
use axum::{
    http::{HeaderValue, header},
    response::Response,
};

const MAX_COOKIE_AGE: f64 = 34_560_000.0;

pub(super) fn core(cookie: &ResolvedCookie, value: &str, max_age: i64) -> String {
    crate::axum::http::serialize_cookie(cookie, value, Some(max_age))
}

pub(super) fn marker(
    cookie: &ResolvedCookie,
    value: &str,
    requested_max_age: Option<f64>,
    force_expiry: bool,
) -> Result<String, AuthError> {
    let mut cookie = cookie.clone();
    apply_prefix_rules(&mut cookie);
    let max_age = if force_expiry {
        Some(0.0)
    } else {
        cookie.attributes.max_age.or(requested_max_age)
    };
    let mut value = format!("{}={value}", cookie.name);
    append_max_age(&mut value, max_age)?;
    if let Some(domain) = &cookie.attributes.domain {
        value.push_str(&format!("; Domain={domain}"));
    }
    if !cookie.attributes.path.is_empty() {
        value.push_str(&format!("; Path={}", cookie.attributes.path));
    }
    append_expires(&mut value, cookie.attributes.expires)?;
    if cookie.attributes.http_only {
        value.push_str("; HttpOnly");
    }
    if cookie.attributes.secure {
        value.push_str("; Secure");
    }
    value.push_str(&format!(
        "; SameSite={}",
        cookie.attributes.same_site.as_str()
    ));
    if cookie.attributes.partitioned {
        value.push_str("; Partitioned");
    }
    Ok(value)
}

fn apply_prefix_rules(cookie: &mut ResolvedCookie) {
    if cookie.name.starts_with("__Secure-") {
        cookie.attributes.secure = true;
    }
    if cookie.name.starts_with("__Host-") {
        cookie.attributes.secure = true;
        cookie.attributes.path = "/".into();
        cookie.attributes.domain = None;
    }
}

fn append_max_age(value: &mut String, max_age: Option<f64>) -> Result<(), AuthError> {
    let Some(max_age) = max_age.filter(|max_age| *max_age >= 0.0) else {
        return Ok(());
    };
    if max_age > MAX_COOKIE_AGE {
        return Err(AuthError::InvalidConfiguration(
            "Cookies Max-Age SHOULD NOT be greater than 400 days (34560000 seconds) in duration."
                .into(),
        ));
    }
    value.push_str(&format!("; Max-Age={}", max_age.floor() as i64));
    Ok(())
}

fn append_expires(
    value: &mut String,
    expires: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), AuthError> {
    let Some(expires) = expires else {
        return Ok(());
    };
    if expires - chrono::Utc::now() > chrono::Duration::days(400) {
        return Err(AuthError::InvalidConfiguration(
            "Cookies Expires SHOULD NOT be greater than 400 days (34560000 seconds) in the future."
                .into(),
        ));
    }
    value.push_str(&format!(
        "; Expires={}",
        expires.format("%a, %d %b %Y %H:%M:%S GMT")
    ));
    Ok(())
}

pub(super) fn append(mut response: Response, cookie: String) -> Response {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

pub(super) fn request_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').map(str::trim).find_map(|cookie| {
        let (key, value) = cookie.split_once('=')?;
        (key == name).then_some(value)
    })
}

pub(super) fn response_value(header: &str, name: &str) -> Option<String> {
    let pair = header.split(';').next()?.trim();
    let (key, value) = pair.split_once('=')?;
    (key == name).then(|| {
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        decode_cookie_component(value)
    })
}
