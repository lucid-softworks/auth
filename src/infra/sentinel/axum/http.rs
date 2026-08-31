use crate::infra::dash::{
    IdentificationCookie, IdentificationIpOptions, IdentificationRequest,
};
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};

const CAPTURED_JSON_LIMIT: usize = 2 * 1024 * 1024;

pub(super) async fn capture_json_body(mut request: Request) -> Result<Request, Response> {
    let body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = to_bytes(body, CAPTURED_JSON_LIMIT).await.map_err(|_| {
        error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
            "Request body is too large",
        )
    })?;
    if let Ok(value) = serde_json::from_slice(&bytes) {
        request
            .extensions_mut()
            .insert(crate::plugin::CapturedPluginRequestBody(value));
    }
    *request.body_mut() = Body::from(bytes);
    Ok(request)
}

pub(super) fn replace_json_body(request: &mut Request, value: serde_json::Value) {
    let bytes = serde_json::to_vec(&value).expect("captured JSON is serializable");
    request
        .extensions_mut()
        .insert(crate::plugin::CapturedPluginRequestBody(value));
    *request.body_mut() = Body::from(bytes);
}

pub(super) fn replace_query_value(request: &mut Request, field: &str, value: &str) {
    let mut pairs: Vec<(String, String)> = request
        .uri()
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    if let Some((_, current)) = pairs.iter_mut().find(|(name, _)| name == field) {
        *current = value.to_owned();
    } else {
        pairs.push((field.to_owned(), value.to_owned()));
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut parts = request.uri().clone().into_parts();
    parts.path_and_query = format!("{}?{query}", request.uri().path()).parse().ok();
    if let Ok(uri) = Uri::from_parts(parts) {
        *request.uri_mut() = uri;
    }
}

pub(super) fn identification_request(
    service: &crate::AuthService,
    request: &Request,
    path: &str,
) -> IdentificationRequest {
    IdentificationRequest {
        method: request.method().clone(),
        path: path.to_owned(),
        headers: request.headers().clone(),
        request_id_cookie: request_cookie(request.headers(), "__infra-rid"),
        ip_options: ip_options(service),
    }
}

pub(super) fn context_identification_request(
    service: &crate::AuthService,
    request: &crate::PluginRequestContext,
    method: Method,
) -> IdentificationRequest {
    let headers = request_headers(request);
    IdentificationRequest {
        method,
        path: request.path.clone(),
        request_id_cookie: request_cookie(&headers, "__infra-rid"),
        headers,
        ip_options: ip_options(service),
    }
}

fn ip_options(service: &crate::AuthService) -> IdentificationIpOptions {
    IdentificationIpOptions {
        ip_address_headers: Some(service.ip_address_headers().to_vec()),
        disable_ip_tracking: service.disable_ip_tracking(),
    }
}

pub(super) fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn request_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (cookie_name, value) = cookie.trim().split_once('=')?;
                (cookie_name == name).then(|| value.to_owned())
            })
        })
}

pub(super) fn cookie_header(cookie: IdentificationCookie) -> Option<HeaderValue> {
    let value = match cookie {
        IdentificationCookie::Set {
            name,
            value,
            max_age_seconds,
            ..
        } => format!(
            "{name}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}",
            crate::cookie::encode_cookie_component(&value)
        ),
        IdentificationCookie::Clear { name, .. } => {
            format!("{name}=; Path=/; Max-Age=0")
        }
    };
    HeaderValue::from_str(&value).ok()
}

fn request_headers(request: &crate::PluginRequestContext) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in &request.headers {
        if let (Ok(name), Ok(value)) = (
            name.parse::<header::HeaderName>(),
            value.parse::<HeaderValue>(),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

pub(super) fn challenge_error(challenge: &str, reason: &str) -> Response {
    let mut response = error(
        StatusCode::LOCKED,
        "POW_CHALLENGE_REQUIRED",
        "Please complete a security check to continue.",
    );
    if let Ok(value) = HeaderValue::from_str(challenge) {
        response.headers_mut().insert("x-pow-challenge", value);
    }
    if let Ok(value) = HeaderValue::from_str(reason) {
        response.headers_mut().insert("x-pow-reason", value);
    }
    response
}

pub(super) fn error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    crate::axum::api_error(status, code, message)
}

pub(super) fn relative_path(path: &str, base_path: &str) -> String {
    let base = base_path.trim_end_matches('/');
    if path == base {
        return "/".into();
    }
    path.strip_prefix(base)
        .filter(|relative| relative.starts_with('/'))
        .unwrap_or(path)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_replacement_preserves_other_values() {
        let mut request = Request::builder()
            .uri("/sign-in/email?email=Old%40Example.com&callbackURL=%2Faccount")
            .body(Body::empty())
            .unwrap();
        replace_query_value(&mut request, "email", "new@example.com");
        assert_eq!(
            request.uri().query(),
            Some("email=new%40example.com&callbackURL=%2Faccount")
        );
    }
}
