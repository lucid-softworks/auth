mod config;
mod profile;

use super::{callback, support};
use crate::{AuthService, SsoPlugin, VerificationValue, service::OAuthState};
use axum::{
    Extension,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use chrono::{Duration, Utc};
use samlet::raw::{Binding, HttpRequest};
use samlet::SsoSession;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

const REQUEST_PREFIX: &str = "saml-authn-request:";
const ASSERTION_PREFIX: &str = "saml-used-assertion:";

#[derive(Debug, Deserialize)]
pub(super) struct AcsBody {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AcsQuery {
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

pub(super) async fn post(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<AcsBody>,
) -> Response {
    if body.saml_response.len() > crate::sso::DEFAULT_MAX_SAML_RESPONSE_SIZE {
        return support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!(
                "SAML response exceeds maximum allowed size ({} bytes)",
                crate::sso::DEFAULT_MAX_SAML_RESPONSE_SIZE
            ),
        );
    }
    let relay_state = match body.relay_state.as_deref().filter(|state| !state.is_empty()) {
        Some(state) => state,
        None => {
            return support::error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "State error: failed to validate relay state",
            );
        }
    };
    let state = match load_state(&service, relay_state).await {
        Ok(state) => state,
        Err(response) => return *response,
    };
    finish(
        &service,
        &plugin,
        &headers,
        &provider_id,
        relay_state,
        body.saml_response,
        state,
    )
    .await
}

pub(super) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<AcsQuery>,
) -> Response {
    if crate::axum::http::current_session_cache_first(&service, &headers)
        .await
        .is_none()
    {
        return callback::redirect_error(
            &format!("{}/error", support::base_url(&service)),
            "invalid_request",
            "invalid_request",
        );
    }
    let target = query.relay_state.filter(|target| {
        crate::axum::validate_trusted_origin_value(&service, &headers, target).is_ok()
    });
    let target = target.unwrap_or_else(|| support::base_url(&service));
    match HeaderValue::from_str(&target) {
        Ok(location) => crate::axum::api_redirect(location),
        Err(_) => support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid callback URL"),
    }
}

async fn finish(
    service: &AuthService,
    plugin: &SsoPlugin,
    headers: &HeaderMap,
    provider_id: &str,
    relay_state: &str,
    saml_response: String,
    state: OAuthState,
) -> Response {
    let error_url = state
        .error_url
        .as_deref()
        .unwrap_or(&state.callback_url)
        .to_owned();
    let Some((request_id, state_reference)) = state_context(&state) else {
        return failure(&error_url, "invalid_state", "sso_provider_reference_missing_or_invalid");
    };
    let (provider, session) = match validate(
        service,
        plugin,
        provider_id,
        relay_state,
        &request_id,
        &state_reference,
        &error_url,
        saml_response,
    )
    .await
    {
        Ok(validated) => validated,
        Err(response) => return *response,
    };
    let Some(saml_config) = provider.saml_config.as_ref().and_then(Value::as_object) else {
        return failure(&error_url, "invalid_provider", "provider not found");
    };
    let user_info = match profile::user_info(
        &session,
        saml_config,
        plugin.options().trust_email_verified,
    ) {
        Ok(user_info) => user_info,
        Err(()) => {
            return failure(
                &error_url,
                "invalid_saml_response",
                "Unable to extract user ID or email from SAML response",
            );
        }
    };
    let result = match service
        .finish_sso_sign_in(
            provider_id,
            user_info,
            state,
            plugin.options().disable_implicit_sign_up,
            crate::axum::http::user_agent(headers),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            let (code, description) = callback::exchange::callback_error(&error);
            return failure(&error_url, code, description);
        }
    };
    let response = callback::exchange::success(service, headers, provider_id, result).await;
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(
            &service.plugin_cookie("relay_state"),
            "",
            Some(0),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
async fn validate(
    service: &AuthService,
    plugin: &SsoPlugin,
    provider_id: &str,
    relay_state: &str,
    request_id: &str,
    state_reference: &super::super::provider_reference::ProviderReference,
    error_url: &str,
    saml_response: String,
) -> Result<(crate::SsoProvider, SsoSession), Box<Response>> {
    let provider = current_provider(plugin, provider_id, state_reference, error_url).await?;
    let config = provider
        .saml_config
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| Box::new(failure(error_url, "invalid_provider", "provider not found")))?;
    let entities = config::entities(service, &provider, config).map_err(|()| {
        Box::new(failure(
            error_url,
            "invalid_saml_response",
            "Invalid SAML response",
        ))
    })?;
    let session = parse_session(entities, relay_state, request_id, saml_response)
        .map_err(|()| Box::new(failure(error_url, "invalid_saml_response", "Invalid SAML response")))?;
    let provider = current_provider(plugin, provider_id, state_reference, error_url).await?;
    consume_security_bindings(
        service,
        provider_id,
        relay_state,
        request_id,
        state_reference,
        &session,
        error_url,
    )
    .await?;
    Ok((provider, session))
}

fn parse_session(
    entities: config::SamlEntities,
    relay_state: &str,
    request_id: &str,
    saml_response: String,
) -> Result<SsoSession, ()> {
    let normalized = saml_response
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    let request = HttpRequest::post(vec![
        ("SAMLResponse".into(), normalized),
        ("RelayState".into(), relay_state.into()),
    ]);
    let parsed = entities
        .sp
        .parse_login_response_with_request_id(
            &entities.idp,
            Binding::Post,
            &request,
            request_id,
        )
        .map_err(|_| ())?;
    SsoSession::try_from(parsed).map_err(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn consume_security_bindings(
    service: &AuthService,
    provider_id: &str,
    relay_state: &str,
    request_id: &str,
    state_reference: &super::super::provider_reference::ProviderReference,
    session: &SsoSession,
    error_url: &str,
) -> Result<(), Box<Response>> {
    consume_request(service, provider_id, request_id, state_reference)
        .await
        .map_err(|()| {
            Box::new(failure(
                error_url,
                "invalid_saml_response",
                "Unknown or expired request ID",
            ))
        })?;
    reserve_assertion(service, provider_id, session)
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

async fn load_state(service: &AuthService, relay_state: &str) -> Result<OAuthState, Box<Response>> {
    let record = service
        .find_verification_value(relay_state)
        .await
        .map_err(|_| Box::new(support::error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "Unable to read relay state")))?
        .ok_or_else(|| Box::new(support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "State error: failed to validate relay state")))?;
    let state: OAuthState = serde_json::from_str(&record.value)
        .map_err(|_| Box::new(support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "State error: failed to validate relay state")))?;
    if record.expires_at < Utc::now() || state.expires_at < Utc::now().timestamp_millis() {
        return Err(Box::new(support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "State error: failed to validate relay state",
        )));
    }
    Ok(state)
}

fn state_context(
    state: &OAuthState,
) -> Option<(String, super::super::provider_reference::ProviderReference)> {
    let context = state.additional_data.get("serverContext")?.as_object()?;
    let request_id = context.get("samlRequestId")?.as_str()?.to_owned();
    let reference = context
        .get("ssoProviderReference")
        .and_then(super::super::provider_reference::parse)?;
    Some((request_id, reference))
}

async fn current_provider(
    plugin: &SsoPlugin,
    provider_id: &str,
    reference: &super::super::provider_reference::ProviderReference,
    error_url: &str,
) -> Result<crate::SsoProvider, Box<Response>> {
    let provider = plugin
        .store()
        .find_by_provider_id(provider_id)
        .await
        .map_err(|error| Box::new(support::storage(error)))?
        .ok_or_else(|| Box::new(support::error(StatusCode::NOT_FOUND, "NOT_FOUND", "No SAML provider found")))?;
    if !reference.is_current(&provider) {
        return Err(Box::new(failure(
            error_url,
            "invalid_state",
            "sso_provider_changed_during_authentication",
        )));
    }
    if plugin.options().domain_verification && provider.domain_verified != Some(true) {
        return Err(Box::new(support::error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Provider domain has not been verified",
        )));
    }
    Ok(provider)
}

async fn consume_request(
    service: &AuthService,
    provider_id: &str,
    request_id: &str,
    expected_reference: &super::super::provider_reference::ProviderReference,
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
        .and_then(super::super::provider_reference::parse)
        .ok_or(())?;
    (reference == *expected_reference).then_some(()).ok_or(())
}

async fn reserve_assertion(
    service: &AuthService,
    provider_id: &str,
    session: &SsoSession,
) -> Result<(), ()> {
    let expiry = session
        .not_on_or_after()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value.as_str()).ok())
        .map(|value| value.with_timezone(&Utc) + Duration::milliseconds(crate::sso::DEFAULT_CLOCK_SKEW_MS))
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

fn failure(base: &str, error: &str, description: &str) -> Response {
    callback::redirect_error(base, error, description)
}
