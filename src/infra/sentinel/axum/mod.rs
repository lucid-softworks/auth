#![allow(clippy::result_large_err)]

use super::{CompromisedPasswordResult, SecurityCheck, SentinelPlugin, VerdictAction};
use crate::infra::dash::{IdentificationContext, IdentificationService};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
    response::Response,
};

mod contract;
mod http;

pub(super) async fn intercept(
    service: &crate::AuthService,
    plugin: &SentinelPlugin,
    mut request: Request,
) -> Result<Request, Response> {
    let path = http::relative_path(request.uri().path(), service.base_path());
    if !contract::should_identify(request.method(), &path) || contract::is_dash_route(&path) {
        return Ok(request);
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        request = http::capture_json_body(request).await?;
    }
    let identification_request = http::identification_request(service, &request, &path);
    let identification = plugin
        .identification_service()
        .identify(&identification_request)
        .await;
    if request.method() != Method::GET && contract::is_protected(&path) {
        let body = request
            .extensions()
            .get::<crate::plugin::CapturedPluginRequestBody>()
            .map(|body| body.0.clone());
        let pow_solution = http::header_value(request.headers(), "x-pow-solution");
        enforce_security(
            plugin,
            &path,
            &identification,
            body.as_ref(),
            pow_solution,
        )
        .await?;
    }
    Ok(request)
}

pub(super) async fn after_response(
    service: &crate::AuthService,
    plugin: &SentinelPlugin,
    request: &crate::PluginRequestContext,
    mut response: Response,
) -> Response {
    let Ok(method) = Method::from_bytes(request.method.as_bytes()) else {
        return response;
    };
    if !contract::should_identify(&method, &request.path)
        || contract::is_dash_route(&request.path)
    {
        return response;
    }
    let identification_request = http::context_identification_request(service, request, method);
    let context = plugin
        .identification_service()
        .identify(&identification_request)
        .await;
    if let Some(cookie) = IdentificationService::cookie_after(&identification_request, &context)
        && let Some(value) = http::cookie_header(cookie)
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    track_password_attempt(plugin, request, &context, response.status()).await;
    response
}

async fn enforce_security(
    plugin: &SentinelPlugin,
    path: &str,
    identification: &IdentificationContext,
    body: Option<&serde_json::Value>,
    pow_solution: Option<String>,
) -> Result<(), Response> {
    if (identification.visitor_id.is_some() || identification.ip.is_some())
        && plugin
            .security_client()
            .is_blocked(
                identification.visitor_id.as_deref().unwrap_or_default(),
                identification.ip.as_deref(),
                identification.request_id.as_deref(),
            )
            .await
    {
        return Err(http::error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Too many failed attempts. Please try again later.",
        ));
    }
    let verdict = plugin
        .security_client()
        .check_security(SecurityCheck {
            visitor_id: identification.visitor_id.clone(),
            request_id: identification.request_id.clone(),
            ip: identification.ip.clone(),
            path: path.to_owned(),
            identifier: contract::request_identifier(body),
            pow_solution,
        })
        .await;
    handle_verdict(plugin, verdict, identification).await?;
    enforce_compromised_password(plugin, path, body).await
}

async fn handle_verdict(
    plugin: &SentinelPlugin,
    verdict: super::SecurityVerdict,
    identification: &IdentificationContext,
) -> Result<(), Response> {
    match verdict.action {
        VerdictAction::Allow => Ok(()),
        VerdictAction::Block => Err(http::error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            contract::block_message(verdict.reason.as_deref()),
        )),
        VerdictAction::Challenge => {
            let Some(visitor_id) = identification.visitor_id.as_deref() else {
                return Ok(());
            };
            let challenge = match verdict.challenge.filter(|value| !value.trim().is_empty()) {
                Some(challenge) => challenge,
                None => {
                    plugin
                        .security_client()
                        .generate_challenge(visitor_id, identification.request_id.as_deref())
                        .await
                }
            };
            if challenge.trim().is_empty() {
                Ok(())
            } else {
                Err(http::challenge_error(
                    &challenge,
                    verdict.reason.as_deref().unwrap_or("unknown"),
                ))
            }
        }
    }
}

async fn enforce_compromised_password(
    plugin: &SentinelPlugin,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<(), Response> {
    if !contract::checks_breached_password(path) {
        return Ok(());
    }
    let Some(password) = contract::password_to_check(body) else {
        return Ok(());
    };
    let compromised = plugin
        .security_client()
        .check_compromised_password(password)
        .await;
    if matches!(
        compromised,
        CompromisedPasswordResult {
            compromised: true,
            action: Some(super::SecurityAction::Block),
            ..
        }
    ) {
        return Err(http::error(
            StatusCode::BAD_REQUEST,
            "COMPROMISED_PASSWORD",
            "This password has been found in data breaches. Please choose a different password.",
        ));
    }
    Ok(())
}

async fn track_password_attempt(
    plugin: &SentinelPlugin,
    request: &crate::PluginRequestContext,
    identification: &IdentificationContext,
    status: StatusCode,
) {
    if !contract::is_password_sign_in(&request.path) {
        return;
    }
    let Some(body) = request.body.as_ref() else {
        return;
    };
    let Some(login_id) = contract::login_identifier(&request.path, body) else {
        return;
    };
    if status.is_client_error() || status.is_server_error() {
        if let (Some(password), Some(visitor_id)) = (
            contract::string_field(body, "password"),
            identification.untrusted_visitor_id.as_deref(),
        ) {
            let _ = plugin
                .security_client()
                .track_failed_attempt(
                    login_id,
                    visitor_id,
                    password,
                    identification.ip.as_deref(),
                    identification.request_id.as_deref(),
                )
                .await;
        }
    } else {
        plugin
            .security_client()
            .clear_failed_attempts(login_id)
            .await;
    }
}
