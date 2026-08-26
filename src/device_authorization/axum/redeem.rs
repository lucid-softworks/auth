use axum::http::StatusCode;
use chrono::Utc;

use super::{DeviceAuthorizationState, error};
use crate::{
    AuthService,
    device_authorization::{DeviceCode, DeviceCodeOwner, DeviceCodeStatus},
};

pub(super) async fn standalone(
    service: &AuthService,
    state: &DeviceAuthorizationState,
    device_code: &str,
    client_id: &str,
) -> Result<(DeviceCode, crate::AuthUser), Box<axum::response::Response>> {
    let record = state
        .store
        .find_device_code(device_code)
        .await
        .map_err(|_| Box::new(error::internal("Unable to look up device code", true)))?
        .ok_or_else(|| Box::new(invalid_device_code()))?;
    validate_standalone_owner(&record, client_id)?;
    let now = Utc::now();
    advance_poll(state, &record, now).await?;
    match record.status {
        DeviceCodeStatus::Pending => {
            return Err(Box::new(error::protocol(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "Authorization pending",
                true,
            )));
        }
        DeviceCodeStatus::Denied => {
            state
                .store
                .delete_device_code(record.id)
                .await
                .map_err(|_| {
                    Box::new(error::internal("Unable to delete denied device code", true))
                })?;
            return Err(Box::new(error::protocol(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "Access denied",
                true,
            )));
        }
        DeviceCodeStatus::Approved => {}
    }
    load_and_consume(service, state, record, client_id).await
}

fn validate_standalone_owner(
    record: &DeviceCode,
    client_id: &str,
) -> Result<(), Box<axum::response::Response>> {
    if record
        .client_id
        .as_deref()
        .is_some_and(|owner| owner != client_id)
    {
        return Err(Box::new(error::protocol(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Client ID mismatch",
            true,
        )));
    }
    if record.oauth_client_id.is_some() {
        return Err(Box::new(error::protocol(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "This device code must be exchanged at the OAuth token endpoint (/oauth2/token).",
            true,
        )));
    }
    Ok(())
}

async fn load_and_consume(
    service: &AuthService,
    state: &DeviceAuthorizationState,
    record: DeviceCode,
    client_id: &str,
) -> Result<(DeviceCode, crate::AuthUser), Box<axum::response::Response>> {
    let Some(user_id) = record.user_id else {
        return Err(Box::new(error::internal(
            "Invalid device code status",
            true,
        )));
    };
    let user = service
        .device_authorization_user(&user_id)
        .await
        .map_err(|_| {
            Box::new(error::internal(
                "Unable to load device authorization user",
                true,
            ))
        })?
        .ok_or_else(|| Box::new(error::internal("User not found", true)))?;
    let claimed = state
        .store
        .consume_approved_device_code(record.id, DeviceCodeOwner::ClientId(client_id.into()))
        .await
        .map_err(|_| Box::new(error::internal("Unable to consume device code", true)))?
        .filter(|claimed| claimed.user_id.is_some())
        .ok_or_else(|| Box::new(invalid_device_code()))?;
    Ok((claimed, user))
}

async fn advance_poll(
    state: &DeviceAuthorizationState,
    record: &DeviceCode,
    now: chrono::DateTime<Utc>,
) -> Result<(), Box<axum::response::Response>> {
    if record.last_polled_at.is_some_and(|last| {
        record.polling_interval.is_some_and(|interval| {
            interval != 0.0
                && ((now.timestamp_millis() - last.timestamp_millis()) as f64) < interval
        })
    }) {
        return Err(Box::new(error::protocol(
            StatusCode::BAD_REQUEST,
            "slow_down",
            "Polling too frequently",
            true,
        )));
    }
    state
        .store
        .update_last_polled_at(record.id, now)
        .await
        .map_err(|_| {
            Box::new(error::internal(
                "Unable to update device-code polling state",
                true,
            ))
        })?;
    if record.expires_at < now {
        state
            .store
            .delete_device_code(record.id)
            .await
            .map_err(|_| {
                Box::new(error::internal(
                    "Unable to delete expired device code",
                    true,
                ))
            })?;
        return Err(Box::new(error::protocol(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "Device code has expired",
            true,
        )));
    }
    Ok(())
}

fn invalid_device_code() -> axum::response::Response {
    error::protocol(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "Invalid device code",
        true,
    )
}
