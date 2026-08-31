use super::{saml_acs::config, support};
use crate::{AuthService, SsoPlugin, VerificationValue};
use axum::{
    Extension,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use samlet::raw::{Binding, HttpRequest, User, logout};
use samlet::LogoutRequest;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

const LOGOUT_REQUEST_PREFIX: &str = "saml-logout-request:";
const SESSION_PREFIX: &str = "saml-session:";
const SESSION_BY_ID_PREFIX: &str = "saml-session-by-id:";

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct SloInput {
    #[serde(rename = "SAMLRequest")]
    saml_request: Option<String>,
    #[serde(rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
    #[serde(rename = "SigAlg")]
    sig_alg: Option<String>,
    #[serde(rename = "Signature")]
    signature: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct InitiateInput {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

pub(super) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Query(input): Query<SloInput>,
) -> Response {
    handle(&service, &plugin, &provider_id, &headers, input, Binding::Redirect).await
}

pub(super) async fn post(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(input): crate::axum::body::BetterAuthBody<SloInput>,
) -> Response {
    handle(&service, &plugin, &provider_id, &headers, input, Binding::Post).await
}

pub(super) async fn initiate(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(input): crate::axum::body::BetterAuthBody<InitiateInput>,
) -> Response {
    if !plugin.options().saml_enable_single_logout {
        return error("SINGLE_LOGOUT_NOT_ENABLED", "SAML single logout is not enabled");
    }
    let Some(actor) = crate::axum::http::current_session_cache_first(&service, &headers).await else {
        return support::error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Authentication required");
    };
    let Some(token) = crate::axum::http::session_token(&service, &headers) else {
        return support::error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Authentication required");
    };
    let Some((provider, entities)) = provider_entities(&service, &plugin, &provider_id).await else {
        return support::error(StatusCode::NOT_FOUND, "SAML_PROVIDER_NOT_FOUND", "SAML provider not found");
    };
    if entities.idp.metadata.get_single_logout_service(Binding::Redirect).is_none() {
        return error("IDP_SLO_NOT_SUPPORTED", "Identity provider does not support single logout");
    }
    let callback = safe_redirect(
        &service,
        &headers,
        input.callback_url.as_deref(),
        &support::base_url(&service),
    );
    let (name_id, session_index, session_key) = session_subject(&service, &actor.session.id, &actor.user.email).await;
    let mut user = User::new(name_id);
    user.session_index = session_index;
    let request = match logout::create_logout_request(
        &entities.sp.setting,
        &entities.sp.metadata,
        &entities.idp.metadata,
        Binding::Redirect,
        &user,
        Some(&callback),
        false,
    ) {
        Ok(request) => request,
        Err(_) => return error("INVALID_LOGOUT_REQUEST", "Unable to create SAML LogoutRequest"),
    };
    let expires_at = Utc::now() + Duration::milliseconds(plugin.options().saml_logout_request_ttl_ms);
    let record = VerificationValue::new(
        format!("{LOGOUT_REQUEST_PREFIX}{}", request.id),
        json!({"providerId": provider.provider_id, "callbackURL": callback}).to_string(),
        expires_at,
    );
    if service.create_verification_value(record).await.is_err() {
        return support::error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "Unable to persist logout request");
    }
    forget_session(&service, &actor.session.id, session_key.as_deref()).await;
    if service.sign_out(&token).await.is_err() {
        return support::error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "Unable to delete session");
    }
    redirect_and_clear(&service, &headers, &request.context)
}

async fn handle(
    service: &AuthService,
    plugin: &SsoPlugin,
    provider_id: &str,
    headers: &HeaderMap,
    input: SloInput,
    binding: Binding,
) -> Response {
    if !plugin.options().saml_enable_single_logout {
        return error("SINGLE_LOGOUT_NOT_ENABLED", "SAML single logout is not enabled");
    }
    if input.saml_request.is_none() && input.saml_response.is_none() {
        let fallback = format!("{}/sso/saml2/sp/slo/{provider_id}", support::base_url(service));
        let target = safe_redirect(service, headers, input.relay_state.as_deref(), &fallback);
        return redirect_error(&target, "missing_logout_data");
    }
    let Some((_, entities)) = provider_entities(service, plugin, provider_id).await else {
        return support::error(StatusCode::NOT_FOUND, "SAML_PROVIDER_NOT_FOUND", "SAML provider not found");
    };
    if input.saml_response.is_some() {
        handle_response(service, headers, provider_id, entities, input, binding).await
    } else {
        handle_request(service, headers, provider_id, entities, input, binding).await
    }
}

async fn handle_response(
    service: &AuthService,
    headers: &HeaderMap,
    provider_id: &str,
    entities: config::SamlEntities,
    input: SloInput,
    binding: Binding,
) -> Response {
    let request = browser_request(&input, binding);
    let preliminary = match logout::parse_logout_response_without_request_id(
        &entities.sp.setting,
        &entities.idp.metadata,
        binding,
        &request,
    ) {
        Ok(parsed) => parsed,
        Err(_) => return error("INVALID_LOGOUT_RESPONSE", "Invalid SAML LogoutResponse"),
    };
    let Some(request_id) = preliminary.extract.get_str("response.inResponseTo") else {
        return error("INVALID_LOGOUT_RESPONSE", "Invalid SAML LogoutResponse");
    };
    let key = format!("{LOGOUT_REQUEST_PREFIX}{request_id}");
    let Some(record) = service.find_verification_value(&key).await.ok().flatten() else {
        return error("INVALID_LOGOUT_RESPONSE", "Unknown or expired logout request");
    };
    let stored: Value = serde_json::from_str(&record.value).unwrap_or(Value::Null);
    if stored.get("providerId").and_then(Value::as_str) != Some(provider_id)
        || logout::parse_logout_response(
            &entities.sp.setting,
            &entities.idp.metadata,
            binding,
            &request,
            request_id,
        )
        .is_err()
    {
        return error("INVALID_LOGOUT_RESPONSE", "Invalid SAML LogoutResponse");
    }
    let _ = service.consume_verification_value(&key, Utc::now()).await;
    let fallback = support::base_url(service);
    let target = safe_redirect(service, headers, input.relay_state.as_deref(), &fallback);
    redirect_and_clear(service, headers, &target)
}

async fn handle_request(
    service: &AuthService,
    headers: &HeaderMap,
    provider_id: &str,
    entities: config::SamlEntities,
    input: SloInput,
    binding: Binding,
) -> Response {
    let parsed = match logout::parse_logout_request(
        &entities.sp.setting,
        &entities.idp.metadata,
        binding,
        &browser_request(&input, binding),
    ) {
        Ok(parsed) => parsed,
        Err(_) => return error("INVALID_LOGOUT_REQUEST", "Invalid SAML LogoutRequest"),
    };
    let request = match LogoutRequest::try_from(parsed) {
        Ok(request) => request,
        Err(_) => return error("INVALID_LOGOUT_REQUEST", "Invalid SAML LogoutRequest"),
    };
    if let Some(name_id) = request.name_id() {
        delete_named_session(
            service,
            provider_id,
            name_id.value(),
            request.session_indexes().first().map(|value| value.as_str()),
        )
        .await;
    }
    if let Some(token) = crate::axum::http::session_token(service, headers) {
        let _ = service.sign_out(&token).await;
    }
    let response = match logout::create_logout_response(
        &entities.sp.setting,
        &entities.sp.metadata,
        &entities.idp.metadata,
        binding,
        Some(request.id().as_str()),
        input.relay_state.as_deref(),
        false,
    ) {
        Ok(response) => response,
        Err(_) => return error("INVALID_LOGOUT_RESPONSE", "Unable to create SAML LogoutResponse"),
    };
    let response = if binding == Binding::Post {
        Html(response.post_form()).into_response()
    } else {
        redirect(&response.context)
    };
    crate::axum::http::clear_session_cookie_from_request(service, headers, response)
}

fn browser_request(input: &SloInput, binding: Binding) -> HttpRequest {
    let fields = [
        ("SAMLRequest", input.saml_request.as_deref()),
        ("SAMLResponse", input.saml_response.as_deref()),
        ("RelayState", input.relay_state.as_deref()),
        ("SigAlg", input.sig_alg.as_deref()),
        ("Signature", input.signature.as_deref()),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| (name.into(), value.into())))
    .collect();
    match binding {
        Binding::Post => HttpRequest::post(fields),
        _ => HttpRequest::redirect(fields),
    }
}

async fn provider_entities(
    service: &AuthService,
    plugin: &SsoPlugin,
    provider_id: &str,
) -> Option<(crate::SsoProvider, config::SamlEntities)> {
    let provider = plugin.find_auth_provider(provider_id).await.ok()??;
    let source = provider.saml_config.as_ref()?.as_object()?;
    let entities = config::entities(service, &provider, source, plugin.options()).ok()?;
    Some((provider, entities))
}

async fn session_subject(
    service: &AuthService,
    session_id: &str,
    fallback: &str,
) -> (String, Option<String>, Option<String>) {
    let by_id = format!("{SESSION_BY_ID_PREFIX}{session_id}");
    let key = service.find_verification_value(&by_id).await.ok().flatten().map(|value| value.value);
    let data = match key.as_deref() {
        Some(key) => service.find_verification_value(key).await.ok().flatten(),
        None => None,
    };
    let data = data.and_then(|value| serde_json::from_str::<Value>(&value.value).ok());
    (
        data.as_ref().and_then(|value| value.get("nameID")).and_then(Value::as_str).unwrap_or(fallback).into(),
        data.as_ref().and_then(|value| value.get("sessionIndex")).and_then(Value::as_str).map(str::to_owned),
        key,
    )
}

async fn forget_session(service: &AuthService, session_id: &str, key: Option<&str>) {
    if let Some(key) = key {
        let _ = service.delete_verification_value(key).await;
    }
    let _ = service.delete_verification_value(&format!("{SESSION_BY_ID_PREFIX}{session_id}")).await;
}

async fn delete_named_session(service: &AuthService, provider_id: &str, name_id: &str, session_index: Option<&str>) {
    let key = format!("{SESSION_PREFIX}{provider_id}:{name_id}");
    let Some(record) = service.find_verification_value(&key).await.ok().flatten() else { return; };
    let data: Value = serde_json::from_str(&record.value).unwrap_or(Value::Null);
    let stored_index = data.get("sessionIndex").and_then(Value::as_str);
    if session_index.is_none() || stored_index.is_none() || session_index == stored_index {
        if let Some(token) = data.get("sessionToken").and_then(Value::as_str) {
            let _ = service.sign_out(token).await;
        }
        if let Some(id) = data.get("sessionId").and_then(Value::as_str) {
            let _ = service.delete_verification_value(&format!("{SESSION_BY_ID_PREFIX}{id}")).await;
        }
    }
    let _ = service.delete_verification_value(&key).await;
}

fn safe_redirect(service: &AuthService, headers: &HeaderMap, candidate: Option<&str>, fallback: &str) -> String {
    candidate
        .filter(|candidate| crate::axum::validate_trusted_origin_value(service, headers, candidate).is_ok())
        .unwrap_or(fallback)
        .to_owned()
}

fn redirect_and_clear(service: &AuthService, headers: &HeaderMap, target: &str) -> Response {
    crate::axum::http::clear_session_cookie_from_request(service, headers, redirect(target))
}

fn redirect(target: &str) -> Response {
    HeaderValue::from_str(target)
        .map(crate::axum::api_redirect)
        .unwrap_or_else(|_| error("INVALID_REDIRECT", "Invalid redirect URL"))
}

fn redirect_error(target: &str, description: &str) -> Response {
    match crate::url_composition::append_query_params(
        target,
        &[
            ("error", "invalid_request"),
            ("error_description", description),
        ],
    ) {
        Ok(location) => redirect(&location),
        Err(_) => error("INVALID_REDIRECT", "Invalid redirect URL"),
    }
}

fn error(code: &'static str, message: &'static str) -> Response {
    support::error(StatusCode::BAD_REQUEST, code, message)
}
