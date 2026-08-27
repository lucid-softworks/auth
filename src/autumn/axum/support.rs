use crate::{AuthService, Organization, SessionWithUser};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};

pub(super) fn error_response(
    logical_status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Response {
    crate::axum::api_error_with_body(
        StatusCode::OK,
        json!({
            "message": message.into(),
            "code": code.into(),
            "statusCode": logical_status.as_u16(),
        }),
    )
}

pub(super) fn validation_error(message: impl Into<String>) -> Response {
    crate::axum::api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message)
}

pub(super) fn success(value: Value) -> Response {
    Json(value).into_response()
}

pub(super) async fn optional_session(
    service: &AuthService,
    headers: &axum::http::HeaderMap,
) -> Option<SessionWithUser> {
    crate::axum::http::current_session(service, headers).await
}

pub(super) async fn active_organization(
    service: &AuthService,
    session: Option<&SessionWithUser>,
) -> Option<Organization> {
    let organization_id = session
        .and_then(|session| {
            session
                .session
                .additional_fields
                .get("activeOrganizationId")
        })
        .and_then(Value::as_str)?;
    let plugin = service.organization_plugin().ok()?;
    plugin
        .store
        .find_organization_by_id(organization_id)
        .await
        .ok()
        .flatten()
}

pub(super) fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}
