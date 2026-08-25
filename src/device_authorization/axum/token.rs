use axum::{Extension, Json, extract::Request, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use serde_json::json;

use super::{DeviceAuthorizationState, error, redeem, request};
use crate::AuthService;

pub(super) async fn exchange(
    Extension(service): Extension<std::sync::Arc<AuthService>>,
    Extension(state): Extension<DeviceAuthorizationState>,
    raw: Request,
) -> axum::response::Response {
    let (headers, input) = match request::token(raw).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    if let Some(validator) = &state.config.validate_client {
        match validator.validate(&input.client_id).await {
            Ok(true) => {}
            Ok(false) => {
                return error::protocol(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "Invalid client ID",
                    true,
                );
            }
            Err(_) => return error::internal("Unable to validate client ID", true),
        }
    }
    let (claimed, user) =
        match redeem::standalone(&service, &state, &input.device_code, &input.client_id).await {
            Ok(result) => result,
            Err(response) => return *response,
        };
    let signed_in = match service
        .create_device_authorization_session(user, &headers)
        .await
    {
        Ok(session) => session,
        Err(_) => return error::internal("Failed to create session", true),
    };
    let expires_in = (signed_in.session.session.expires_at - Utc::now())
        .num_seconds()
        .max(0);
    error::no_store(
        Json(json!({
            "access_token": signed_in.token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": claimed.scope.unwrap_or_default(),
        }))
        .into_response(),
    )
}
