use crate::{AgentAuthApiError, AgentAuthErrorCode, AuthService};
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value};

pub(super) fn api_error(
    status: StatusCode,
    code: AgentAuthErrorCode,
    message: Option<String>,
    extra: Map<String, Value>,
) -> Response {
    let mut error = AgentAuthApiError::new(status.as_u16(), code);
    if let Some(message) = message {
        error.message = message;
    }
    error.extra = extra;
    (status, Json(error.body())).into_response()
}

pub(super) fn provided_error(error: AgentAuthApiError) -> Response {
    let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = error.headers.clone();
    let mut response = (status, Json(error.body())).into_response();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::try_from(name),
            HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

pub(super) fn unauthorized(service: &AuthService, headers: &HeaderMap) -> Response {
    let mut response = api_error(
        StatusCode::UNAUTHORIZED,
        AgentAuthErrorCode::UnauthorizedSession,
        None,
        Map::new(),
    );
    let base_url = super::super::issuer(service, headers);
    if let Ok(challenge) = crate::agent_auth_challenge(&base_url)
        && let Ok(value) = HeaderValue::from_str(&challenge)
    {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}
