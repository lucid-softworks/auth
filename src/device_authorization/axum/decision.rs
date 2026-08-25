use axum::{Extension, Json, extract::Request, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use serde_json::json;

use super::{DeviceAuthorizationState, error, lookup, request};
use crate::{AuthService, device_authorization::DeviceCodeStatus};

pub(super) async fn approve(
    service: Extension<std::sync::Arc<AuthService>>,
    state: Extension<DeviceAuthorizationState>,
    request: Request,
) -> axum::response::Response {
    decide(service, state, request, Decision::Approve).await
}

pub(super) async fn deny(
    service: Extension<std::sync::Arc<AuthService>>,
    state: Extension<DeviceAuthorizationState>,
    request: Request,
) -> axum::response::Response {
    decide(service, state, request, Decision::Deny).await
}

async fn decide(
    Extension(service): Extension<std::sync::Arc<AuthService>>,
    Extension(state): Extension<DeviceAuthorizationState>,
    raw: Request,
    decision: Decision,
) -> axum::response::Response {
    let (headers, user_code) = match request::decision(raw).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    let Some(session) = crate::axum::http::current_session_cache_first(&service, &headers).await
    else {
        return error::protocol(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication required",
            false,
        );
    };
    let record = match lookup::by_user_code(state.store.as_ref(), &user_code).await {
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
    if record.status != DeviceCodeStatus::Pending {
        return error::protocol(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device code already processed",
            false,
        );
    }
    let Some(owner) = record.user_id else {
        return error::protocol(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying",
            false,
        );
    };
    if owner != session.user.id {
        return error::protocol(
            StatusCode::FORBIDDEN,
            "access_denied",
            format!(
                "You are not authorized to {} this device authorization",
                decision.verb()
            ),
            false,
        );
    }
    if state
        .store
        .update_device_code_status(record.id, decision.status())
        .await
        .is_err()
    {
        return error::internal("Unable to update device authorization", false);
    }
    Json(json!({"success": true})).into_response()
}

#[derive(Clone, Copy)]
enum Decision {
    Approve,
    Deny,
}

impl Decision {
    fn status(self) -> DeviceCodeStatus {
        match self {
            Self::Approve => DeviceCodeStatus::Approved,
            Self::Deny => DeviceCodeStatus::Denied,
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}
