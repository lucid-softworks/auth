mod access;
mod oidc;
mod persistence;
mod saml;

use super::support;
use crate::{AuthService, SsoPlugin};
use axum::{Extension, http::HeaderMap, response::Response};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RegisterBody {
    provider_id: String,
    issuer: String,
    domain: String,
    oidc_config: Option<oidc::RegistrationConfig>,
    saml_config: Option<Value>,
    organization_id: Option<String>,
    #[serde(default)]
    override_user_info: bool,
}

pub(super) async fn register(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<RegisterBody>,
) -> Response {
    let session = match support::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = access::validate(&service, &plugin, &body, &session.user.id).await {
        return *response;
    }
    let oidc_config = match body.oidc_config.as_ref() {
        Some(config) => match oidc::prepare(
            &service,
            &plugin,
            &body.provider_id,
            &body.issuer,
            body.override_user_info,
            config,
        )
        .await
        {
            Ok(config) => Some(config),
            Err(response) => return *response,
        },
        None => None,
    };
    let saml_config = match body.saml_config.as_ref() {
        Some(config) => match saml::prepare(&body.issuer, config) {
            Ok(config) => Some(config),
            Err(response) => return *response,
        },
        None => None,
    };
    persistence::create(
        &service,
        &plugin,
        session.user.id,
        body,
        oidc_config,
        saml_config,
    )
    .await
}
