use axum::{Extension, Json, extract::Request, http::StatusCode, response::IntoResponse};
use chrono::{DateTime, Utc};
use serde_json::json;

use super::{DeviceAuthorizationState, error, generation, request, uri};
use crate::AuthService;
use crate::device_authorization::{DeviceCode, DeviceCodeCreateOutcome, DeviceCodeStatus};

const MAX_GENERATION_ATTEMPTS: usize = 3;

struct PreparedRequest {
    client_id: String,
    user_id: Option<String>,
    scope: Option<String>,
    expires_at: DateTime<Utc>,
    expires_ms: f64,
    interval_ms: f64,
}

pub(super) async fn issue(
    Extension(service): Extension<std::sync::Arc<AuthService>>,
    Extension(state): Extension<DeviceAuthorizationState>,
    raw: Request,
) -> axum::response::Response {
    let oauth_mode = state.config.includes_oauth_fields();
    let (headers, input) = match request::code(raw, oauth_mode).await {
        Ok(input) => input,
        Err(response) => return *response,
    };
    if oauth_mode {
        return crate::device_authorization::oauth::issue_code(
            service,
            state.config,
            state.store,
            headers,
            input,
        )
        .await;
    }
    let prepared = match prepare(&state, input).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    create(&service, &state, &headers, prepared).await
}

async fn prepare(
    state: &DeviceAuthorizationState,
    input: request::CodeInput,
) -> Result<PreparedRequest, Box<axum::response::Response>> {
    let Some(client_id) = input.client_id.as_deref() else {
        return Err(Box::new(error::protocol(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
            true,
        )));
    };
    if let Some(validator) = &state.config.validate_client {
        match validator.validate(client_id).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(Box::new(error::protocol(
                    StatusCode::BAD_REQUEST,
                    "invalid_client",
                    "Invalid client ID",
                    true,
                )));
            }
            Err(_) => {
                return Err(Box::new(error::internal(
                    "Unable to validate client ID",
                    true,
                )));
            }
        }
    }
    if let Some(observer) = &state.config.on_device_auth_request
        && observer
            .on_device_auth_request(client_id, input.scope.as_deref())
            .await
            .is_err()
    {
        return Err(Box::new(error::internal(
            "Unable to process device authorization request",
            true,
        )));
    }
    let expires_ms = state
        .config
        .expires_in_milliseconds()
        .map_err(|_| Box::new(error::internal("Invalid device-code expiration", true)))?;
    let interval_ms = state.config.interval_milliseconds().map_err(|_| {
        Box::new(error::internal(
            "Invalid device-code polling interval",
            true,
        ))
    })?;
    let expires_at = javascript_expiry(Utc::now(), expires_ms)
        .ok_or_else(|| Box::new(error::internal("Invalid device-code expiration", true)))?;
    let user_id = input.user_id;
    Ok(PreparedRequest {
        client_id: client_id.to_owned(),
        user_id,
        scope: input.scope,
        expires_at,
        expires_ms,
        interval_ms,
    })
}

async fn create(
    service: &AuthService,
    state: &DeviceAuthorizationState,
    headers: &axum::http::HeaderMap,
    prepared: PreparedRequest,
) -> axum::response::Response {
    for _ in 0..MAX_GENERATION_ATTEMPTS {
        let (device_code, user_code) = match generate_pair(state).await {
            Ok(pair) => pair,
            Err(response) => return *response,
        };
        let record = DeviceCode {
            id: String::new(),
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            user_id: prepared.user_id.clone(),
            expires_at: prepared.expires_at,
            status: DeviceCodeStatus::Pending,
            last_polled_at: None,
            polling_interval: Some(prepared.interval_ms),
            client_id: Some(prepared.client_id.clone()),
            scope: prepared.scope.clone(),
            resources: None,
            oauth_client_id: None,
        };
        match service
            .create_device_authorization_code(state.store.as_ref(), record)
            .await
        {
            Ok(DeviceCodeCreateOutcome::UniqueConflict) => continue,
            Err(_) => return error::internal("Failed to create device code", true),
            Ok(DeviceCodeCreateOutcome::Created(_)) => {
                let (verification_uri, verification_uri_complete) = match uri::verification_uris(
                    service,
                    headers,
                    state.config.verification_uri.as_deref(),
                    &user_code,
                ) {
                    Ok(uris) => uris,
                    Err(_) => return error::internal("Failed to build verification URI", true),
                };
                return error::no_store(
                    Json(json!({
                        "device_code": device_code,
                        "user_code": user_code,
                        "verification_uri": verification_uri,
                        "verification_uri_complete": verification_uri_complete,
                        "expires_in": (prepared.expires_ms / 1_000.0).floor() as i64,
                        "interval": (prepared.interval_ms / 1_000.0).floor() as i64,
                    }))
                    .into_response(),
                );
            }
        }
    }
    error::internal("Failed to generate a unique device code", true)
}

async fn generate_pair(
    state: &DeviceAuthorizationState,
) -> Result<(String, String), Box<axum::response::Response>> {
    let device = generation::device_code(&state.config)
        .await
        .map_err(|error| Box::new(generation_error(error)))?;
    let user = generation::user_code(&state.config)
        .await
        .map_err(|error| Box::new(generation_error(error)))?;
    Ok((device, user))
}

fn generation_error(error: generation::GenerationError) -> axum::response::Response {
    match error {
        generation::GenerationError::TooLong(label) => error::protocol(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            format!("Generated {label} code must be at most 191 characters"),
            true,
        ),
        generation::GenerationError::Failed(label) => {
            error::internal(format!("Failed to generate {label} code"), true)
        }
    }
}

fn javascript_expiry(now: DateTime<Utc>, milliseconds: f64) -> Option<DateTime<Utc>> {
    let timestamp = (now.timestamp_millis() as f64 + milliseconds).trunc();
    if !timestamp.is_finite() || timestamp < i64::MIN as f64 || timestamp > i64::MAX as f64 {
        return None;
    }
    DateTime::from_timestamp_millis(timestamp as i64)
}
