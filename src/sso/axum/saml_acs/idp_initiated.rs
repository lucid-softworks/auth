use super::{config, profile, security};
use crate::{AuthService, SsoPlugin, service::OAuthState};
use axum::{http::HeaderMap, response::Response};
use chrono::{Duration, Utc};
use samlet::raw::{Binding, HttpRequest};
use samlet::SsoSession;
use serde_json::{Map, Value};

pub(super) async fn finish(
    service: &AuthService,
    plugin: &SsoPlugin,
    headers: &HeaderMap,
    provider_id: &str,
    saml_response: String,
) -> Response {
    let provider = match plugin.find_auth_provider(provider_id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => return super::support::error(axum::http::StatusCode::NOT_FOUND, "NOT_FOUND", "No SAML provider found"),
        Err(error) => return super::support::storage(error),
    };
    if plugin.options().domain_verification && provider.domain_verified != Some(true) {
        return super::support::error(
            axum::http::StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Provider domain has not been verified",
        );
    }
    let Some(source) = provider.saml_config.as_ref().and_then(Value::as_object) else {
        return super::support::error(axum::http::StatusCode::NOT_FOUND, "NOT_FOUND", "No SAML provider found");
    };
    let callback = safe_callback(service, headers, provider_id, source, plugin.options());
    let session = match verify(
        service,
        plugin,
        &provider,
        source,
        provider_id,
        saml_response,
        &callback,
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let user_info = match profile::user_info(&session, source, plugin.options().trust_email_verified) {
        Ok(user_info) => user_info,
        Err(()) => return failure(&callback, "invalid_saml_response", "Unable to extract user ID or email from SAML response"),
    };
    let state = OAuthState {
        oauth_state: None,
        callback_url: callback.clone(),
        code_verifier: String::new(),
        error_url: Some(callback.clone()),
        new_user_url: None,
        expires_at: (Utc::now() + Duration::minutes(5)).timestamp_millis(),
        request_sign_up: true,
        id_token_nonce: None,
        additional_data: Map::new(),
        link: None,
        anonymous_user_id: None,
    };
    let provider_reference = super::super::super::provider_reference::current(&provider);
    super::complete_sign_in(
        service,
        plugin,
        &provider,
        provider_reference,
        headers,
        provider_id,
        user_info,
        state,
        &session,
        &callback,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn verify(
    service: &AuthService,
    plugin: &SsoPlugin,
    provider: &crate::SsoProvider,
    source: &Map<String, Value>,
    provider_id: &str,
    saml_response: String,
    callback: &str,
) -> Result<SsoSession, Box<Response>> {
    let entities = config::entities(service, provider, source, plugin.options())
        .map_err(|()| Box::new(failure(callback, "invalid_saml_response", "Invalid SAML response")))?;
    let request = HttpRequest::post(vec![(
        "SAMLResponse".into(),
        saml_response.chars().filter(|value| !value.is_whitespace()).collect(),
    )]);
    let parsed = entities
        .sp
        .parse_login_response(&entities.idp, Binding::Post, &request)
        .map_err(|_| Box::new(failure(callback, "unsolicited_response", "IdP-initiated SSO not allowed or invalid")))?;
    let session = SsoSession::try_from(parsed)
        .map_err(|_| Box::new(failure(callback, "invalid_saml_response", "Invalid SAML response")))?;
    crate::sso::validate_response_algorithms(&session, &plugin.options().saml_algorithms)
        .map_err(|error| Box::new(failure(callback, "invalid_saml_response", &error.message)))?;
    if plugin.options().saml_require_timestamps
        && session.not_before().is_none()
        && session.not_on_or_after().is_none()
    {
        return Err(Box::new(failure(callback, "invalid_saml_response", "SAML assertion missing required timestamp conditions")));
    }
    security::reserve_unsolicited_assertion(
        service,
        provider_id,
        &session,
        plugin.options().saml_clock_skew_ms,
    )
    .await
    .map_err(|()| Box::new(failure(callback, "replay_detected", "SAML assertion has already been used")))?;
    Ok(session)
}

fn safe_callback(
    service: &AuthService,
    headers: &HeaderMap,
    provider_id: &str,
    config: &Map<String, Value>,
    options: &crate::SsoOptions,
) -> String {
    let base = super::support::base_url(service);
    let app_origin = url::Url::parse(&base)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| base.clone());
    let callback_path = format!("{base}/sso/saml2/sp/acs/{provider_id}");
    let callback_path = url::Url::parse(&callback_path)
        .ok()
        .map(|url| url.path().to_owned())
        .unwrap_or_default();
    [
        config.get("idpInitiatedCallbackUrl").and_then(Value::as_str),
        options.saml_idp_initiated_callback_url.as_deref(),
        config.get("callbackUrl").and_then(Value::as_str),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| safe_candidate(service, headers, candidate, &app_origin, &callback_path))
    .unwrap_or(&app_origin)
    .to_owned()
}

fn safe_candidate(
    service: &AuthService,
    headers: &HeaderMap,
    candidate: &str,
    app_origin: &str,
    callback_path: &str,
) -> bool {
    if candidate.starts_with("//") {
        return false;
    }
    let parsed = if candidate.starts_with('/') {
        url::Url::parse(app_origin).and_then(|base| base.join(candidate))
    } else {
        url::Url::parse(candidate)
    };
    let Ok(parsed) = parsed else { return false; };
    parsed.path() != callback_path
        && crate::axum::validate_trusted_origin_value(service, headers, candidate).is_ok()
}

fn failure(base: &str, error: &str, description: &str) -> Response {
    super::super::callback::redirect_error(base, error, description)
}
