use super::{ASSERTION_PREFIX, REQUEST_PREFIX, failure};
use crate::{AuthService, SsoPlugin, VerificationValue, service::OAuthState};
use axum::{http::StatusCode, response::Response};
use chrono::{Duration, Utc};
use samlet::SsoSession;
use serde_json::{Value, json};

type ProviderReference = super::super::super::provider_reference::ProviderReference;

pub(super) async fn load_state(
    service: &AuthService,
    relay_state: &str,
) -> Result<OAuthState, Box<Response>> {
    let invalid = || {
        Box::new(super::support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "State error: failed to validate relay state",
        ))
    };
    let record = service
        .find_verification_value(relay_state)
        .await
        .map_err(|_| {
            Box::new(super::support::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                "Unable to read relay state",
            ))
        })?
        .ok_or_else(invalid)?;
    let state: OAuthState = serde_json::from_str(&record.value).map_err(|_| invalid())?;
    if record.expires_at < Utc::now() || state.expires_at < Utc::now().timestamp_millis() {
        return Err(invalid());
    }
    Ok(state)
}

pub(super) fn state_context(state: &OAuthState) -> Option<(String, ProviderReference)> {
    let context = state.additional_data.get("serverContext")?.as_object()?;
    let request_id = context.get("samlRequestId")?.as_str()?.to_owned();
    let reference = context
        .get("ssoProviderReference")
        .and_then(super::super::super::provider_reference::parse)?;
    Some((request_id, reference))
}

pub(super) async fn current_provider(
    plugin: &SsoPlugin,
    provider_id: &str,
    reference: &ProviderReference,
    error_url: &str,
) -> Result<crate::SsoProvider, Box<Response>> {
    let provider = plugin
        .store()
        .find_by_provider_id(provider_id)
        .await
        .map_err(|error| Box::new(super::support::storage(error)))?
        .ok_or_else(|| {
            Box::new(super::support::error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "No SAML provider found",
            ))
        })?;
    if !reference.is_current(&provider) {
        return Err(Box::new(failure(
            error_url,
            "invalid_state",
            "sso_provider_changed_during_authentication",
        )));
    }
    if plugin.options().domain_verification && provider.domain_verified != Some(true) {
        return Err(Box::new(super::support::error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Provider domain has not been verified",
        )));
    }
    Ok(provider)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn consume_bindings(
    service: &AuthService,
    provider_id: &str,
    relay_state: &str,
    request_id: &str,
    reference: &ProviderReference,
    session: &SsoSession,
    clock_skew_ms: i64,
    error_url: &str,
) -> Result<(), Box<Response>> {
    consume_request(service, provider_id, request_id, reference)
        .await
        .map_err(|()| {
            Box::new(failure(
                error_url,
                "invalid_saml_response",
                "Unknown or expired request ID",
            ))
        })?;
    reserve_assertion(service, provider_id, session, clock_skew_ms)
        .await
        .map_err(|()| {
            Box::new(failure(
                error_url,
                "replay_detected",
                "SAML assertion has already been used",
            ))
        })?;
    match service.consume_verification_value(relay_state, Utc::now()).await {
        Ok(Some(_)) => Ok(()),
        _ => Err(Box::new(failure(
            error_url,
            "invalid_state",
            "invalid_or_expired_relay_state",
        ))),
    }
}

async fn consume_request(
    service: &AuthService,
    provider_id: &str,
    request_id: &str,
    expected_reference: &ProviderReference,
) -> Result<(), ()> {
    let record = service
        .consume_verification_value(&format!("{REQUEST_PREFIX}{request_id}"), Utc::now())
        .await
        .map_err(|_| ())?
        .ok_or(())?;
    let stored: Value = serde_json::from_str(&record.value).map_err(|_| ())?;
    if stored.get("providerId").and_then(Value::as_str) != Some(provider_id) {
        return Err(());
    }
    let reference = stored
        .get("providerReference")
        .and_then(super::super::super::provider_reference::parse)
        .ok_or(())?;
    (reference == *expected_reference).then_some(()).ok_or(())
}

async fn reserve_assertion(
    service: &AuthService,
    provider_id: &str,
    session: &SsoSession,
    clock_skew_ms: i64,
) -> Result<(), ()> {
    let expiry = session
        .not_on_or_after()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value.as_str()).ok())
        .map(|value| value.with_timezone(&Utc) + Duration::milliseconds(clock_skew_ms))
        .unwrap_or_else(|| Utc::now() + Duration::minutes(15));
    let assertion_id = session.assertion_id().as_str();
    let reserved = service
        .reserve_verification_value(VerificationValue::new(
            format!("{ASSERTION_PREFIX}{assertion_id}"),
            json!({
                "assertionId": assertion_id,
                "issuer": session.issuer().as_str(),
                "providerId": provider_id,
                "usedAt": Utc::now().timestamp_millis(),
                "expiresAt": expiry.timestamp_millis()
            })
            .to_string(),
            expiry,
        ))
        .await
        .map_err(|_| ())?;
    reserved.then_some(()).ok_or(())
}
