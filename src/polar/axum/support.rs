use super::input::InputError;
use crate::{AuthService, SessionWithUser};
use axum::{
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};
use url::Url;

pub(super) fn bad_input(error: InputError) -> Response {
    error_response(StatusCode::BAD_REQUEST, "BAD_REQUEST", error.message())
}

pub(super) fn error_response(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    crate::axum::api_error(status, code, message.into())
}

pub(super) fn bad_request(message: &'static str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
}

pub(super) fn unauthorized(message: &'static str) -> Response {
    error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message)
}

pub(super) fn internal(message: &'static str) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        message,
    )
}

pub(super) async fn optional_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<SessionWithUser> {
    crate::axum::http::current_session(service, headers).await
}

pub(super) fn callback_url(
    service: &AuthService,
    headers: &HeaderMap,
    uri: &Uri,
    value: Option<&str>,
) -> Result<Option<String>, url::ParseError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if Url::parse(value).is_ok() {
        return Ok(Some(value.to_owned()));
    }
    request_url(service, headers, uri)
        .and_then(|base| base.join(value))
        .map(|url| Some(url.to_string()))
}

pub(super) fn themed_url(value: &str, theme: Option<&str>) -> Result<String, url::ParseError> {
    let mut url = Url::parse(value)?;
    if let Some(theme) = theme {
        let entries = url
            .query_pairs()
            .filter(|(key, _)| key != "theme")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .chain(std::iter::once(("theme".into(), theme.into())))
            .collect::<Vec<_>>();
        url.query_pairs_mut().clear().extend_pairs(entries);
    }
    Ok(url.to_string())
}

fn request_url(
    service: &AuthService,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<Url, url::ParseError> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Url::parse(&uri.to_string());
    }
    let scheme = header_text(headers, "x-forwarded-proto").unwrap_or("http");
    if let Some(host) = header_text(headers, "x-forwarded-host")
        .or_else(|| header_text(headers, header::HOST.as_str()))
    {
        return Url::parse(&format!("{scheme}://{host}{uri}"));
    }
    let mut base = service
        .configured_base_url()
        .cloned()
        .ok_or(url::ParseError::RelativeUrlWithoutBase)?;
    base.set_path(uri.path());
    base.set_query(uri.query());
    Ok(base)
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_is_replaced_without_disturbing_other_query_parameters() {
        assert_eq!(
            themed_url("https://polar.sh/checkout?a=1&theme=light", Some("dark")).unwrap(),
            "https://polar.sh/checkout?a=1&theme=dark"
        );
    }

    #[test]
    fn no_theme_preserves_provider_url_exactly() {
        let value = "https://polar.sh/checkout?theme=provider";
        assert_eq!(themed_url(value, None).unwrap(), value);
    }
}
