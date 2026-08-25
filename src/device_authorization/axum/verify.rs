use axum::{
    Extension, Json,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde_json::{Map, Value, json};

use super::{DeviceAuthorizationState, error, lookup};
use crate::{AuthService, device_authorization::DeviceCodeStatus};

pub(super) async fn verify(
    Extension(service): Extension<std::sync::Arc<AuthService>>,
    Extension(state): Extension<DeviceAuthorizationState>,
    request: Request,
) -> Response {
    let user_code = match query_user_code(request.uri().query()) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut record = match lookup::by_user_code(state.store.as_ref(), &user_code).await {
        Ok(Some(record)) => record,
        Ok(None) => {
            return error::protocol(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid user code",
                false,
            );
        }
        Err(_) => return error::internal("Unable to look up user code", false),
    };
    if record.expires_at < Utc::now() {
        return error::protocol(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "User code has expired",
            false,
        );
    }
    let session = crate::axum::http::current_session_cache_first(&service, request.headers()).await;
    if let Some(session) = &session
        && record.user_id.is_none()
        && record.status == DeviceCodeStatus::Pending
    {
        match state
            .store
            .bind_pending_user(record.id, session.user.id)
            .await
        {
            Ok(Some(bound)) => record = bound,
            Ok(None) => {}
            Err(_) => return error::internal("Unable to claim device authorization", false),
        }
    }
    let can_review = session
        .as_ref()
        .is_some_and(|session| record.user_id == Some(session.user.id));
    let mut response = Map::from_iter([
        ("user_code".into(), Value::String(user_code)),
        ("status".into(), Value::String(record.status.to_string())),
    ]);
    if can_review {
        if let Some(client_id) = record.client_id {
            response.insert("client_id".into(), Value::String(client_id));
        }
        if let Some(scope) = record.scope {
            response.insert("scope".into(), Value::String(scope));
        }
    }
    Json(json!(response)).into_response()
}

#[allow(clippy::result_large_err)]
fn query_user_code(query: Option<&str>) -> Result<String, Response> {
    let values = query
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .filter(|(name, _)| name == "user_code")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(value.clone()),
        [] => Err(error::validation(
            "[query.user_code] Invalid input: expected string, received undefined",
        )),
        _ => Err(error::validation(
            "[query.user_code] Invalid input: expected string, received array",
        )),
    }
}
