mod authorization;
mod oidc;
mod provider;

use super::support;
use crate::{AuthService, SsoPlugin};
use axum::{Extension, response::Response};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SignInBody {
    email: Option<String>,
    organization_slug: Option<String>,
    provider_id: Option<String>,
    domain: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: String,
    #[serde(rename = "errorCallbackURL")]
    error_callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    scopes: Option<Vec<String>>,
    login_hint: Option<String>,
    additional_params: Option<Map<String, Value>>,
    request_sign_up: Option<bool>,
    provider_type: Option<ProviderType>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ProviderType {
    Oidc,
    Saml,
}

pub(super) async fn sign_in(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<SignInBody>,
) -> Response {
    let provider = match provider::resolve(&service, &plugin, &body).await {
        Ok(provider) => provider,
        Err(response) => return *response,
    };
    if body.provider_type == Some(ProviderType::Oidc) && provider.oidc_config.is_none() {
        return support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "OIDC provider is not configured",
        );
    }
    if body.provider_type == Some(ProviderType::Saml) && provider.saml_config.is_none() {
        return support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "SAML provider is not configured",
        );
    }
    if plugin.options().domain_verification && provider.domain_verified != Some(true) {
        return support::error(
            axum::http::StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Provider domain has not been verified",
        );
    }
    if let Some(config) = provider
        .oidc_config
        .as_ref()
        .and_then(Value::as_object)
        .filter(|_| body.provider_type != Some(ProviderType::Saml))
    {
        return oidc::start(&service, &provider, config, body).await;
    }
    if provider.saml_config.is_some() {
        let message = if body.additional_params.is_some() {
            "additionalParams is not supported for SAML providers; the SAML AuthnRequest is signed and cannot carry caller-supplied query parameters."
        } else {
            "Invalid SAML request"
        };
        return support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            message,
        );
    }
    support::error(
        axum::http::StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "Invalid SSO provider",
    )
}
