use super::{cookies, input::hook_query};
use crate::{AuthService, PluginRequestContext};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};

pub(super) async fn after_response(
    service: &AuthService,
    options: &super::ElectronOptions,
    request: &PluginRequestContext,
    mut response: Response,
) -> Response {
    let is_matching = matches_auth_flow(&request.path);
    let query = hook_query(request.query.as_deref());
    if is_matching
        && (request.path.starts_with("/sign-in") || request.path.starts_with("/sign-up"))
        && query
            .as_ref()
            .is_some_and(|query| query.client_id == options.client_id)
    {
        response = cookies::set_transfer(
            service,
            options,
            query.as_ref().expect("the query was checked"),
            response,
        );
    }

    let Some(session) = response
        .extensions()
        .get::<crate::axum::http::BoundSession>()
        .map(|bound| bound.0.clone())
    else {
        return response;
    };
    let headers = request_headers(request);
    if !is_matching {
        let Some(payload) = cookies::configured_transfer_from_request(service, options, &headers)
        else {
            return response;
        };
        return cookies::set_transfer(service, options, &payload, response);
    }

    let request_payload = cookies::core_transfer_from_request(service, &headers);
    response = cookies::clear_transfer(service, response);
    let payload =
        request_payload.or_else(|| query.filter(|query| query.client_id == options.client_id));
    let Some(payload) = payload else {
        return response;
    };
    let issued = match crate::electron::transfer::issue(
        service,
        options,
        &session.user.id,
        &payload.state,
        &payload.code_challenge,
    )
    .await
    {
        Ok(issued) => issued,
        Err(error) => return replace_with_error(response, error),
    };
    response = cookies::set_redirect(service, options, &issued.redirect_token, response);
    append_authorization_code(response, &issued.identifier).await
}

fn matches_auth_flow(path: &str) -> bool {
    [
        "/sign-in",
        "/sign-up",
        "/callback",
        "/magic-link/verify",
        "/email-otp/verify-email",
        "/verify-email",
        "/one-tap/callback",
        "/passkey/verify-authentication",
        "/phone-number/verify",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

fn request_headers(request: &PluginRequestContext) -> HeaderMap {
    request
        .headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.parse::<axum::http::HeaderName>().ok()?;
            let value = HeaderValue::from_str(value).ok()?;
            Some((name, value))
        })
        .collect()
}

async fn append_authorization_code(response: Response, identifier: &str) -> Response {
    let (mut parts, body) = response.into_parts();
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return Response::from_parts(parts, Body::empty()),
    };
    let mut returned = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    returned.insert(
        "electron_authorization_code".into(),
        serde_json::Value::String(identifier.to_owned()),
    );
    let body = serde_json::to_vec(&returned).unwrap_or_else(|_| b"{}".to_vec());
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(body))
}

fn replace_with_error(mut response: Response, error: crate::AuthError) -> Response {
    let failure = crate::axum::http::auth_error(error);
    *response.status_mut() = failure.status();
    response.headers_mut().extend(failure.headers().clone());
    *response.body_mut() = failure.into_body();
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_has_only_the_nine_published_prefixes() {
        for path in [
            "/sign-in/email",
            "/sign-up/email",
            "/callback/google",
            "/magic-link/verify-extra",
            "/email-otp/verify-email",
            "/verify-email",
            "/one-tap/callback",
            "/passkey/verify-authentication",
            "/phone-number/verify",
        ] {
            assert!(matches_auth_flow(path), "{path}");
        }
        for path in ["/electron/token", "/get-session", "/phone-number/send-otp"] {
            assert!(!matches_auth_flow(path), "{path}");
        }
    }
}
