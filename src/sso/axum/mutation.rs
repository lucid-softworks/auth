mod config;
pub(crate) mod guard;

use super::{sanitize, support};
use crate::{AuthService, SsoPlugin, SsoStoreError};
use axum::{
    Extension, Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateBody {
    provider_id: String,
    issuer: Option<String>,
    domain: Option<String>,
    oidc_config: Option<Map<String, Value>>,
    saml_config: Option<Map<String, Value>>,
    #[serde(flatten)]
    additional_fields: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DeleteBody {
    provider_id: String,
}

pub(super) async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<UpdateBody>,
) -> Response {
    let (_, provider) =
        match support::authorized_provider(&service, &plugin, &headers, &body.provider_id).await {
        Ok(authorized) => authorized,
        Err(response) => return *response,
    };
    let additional_fields = match support::update_additional_fields(&plugin, body.additional_fields.clone()) {
        Ok(fields) => fields,
        Err(response) => return *response,
    };
    let prepared = match config::prepare(&service, &plugin, &provider, &body, additional_fields) {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let provider = match guard::update(
        &service,
        &plugin,
        &provider,
        prepared.update,
        prepared.identity_boundary_changed,
    )
    .await
    {
        Ok(provider) => provider,
        Err(crate::AuthError::SsoStore(SsoStoreError::LinkedAccounts)) => {
            return support::error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot change SSO provider identity fields while linked accounts exist",
            );
        }
        Err(crate::AuthError::SsoStore(SsoStoreError::NotFound)) => return not_found(),
        Err(crate::AuthError::SsoProviderMutationRejected) => return mutation_rejected(),
        Err(crate::AuthError::SsoStore(error)) => return support::storage(error),
        Err(error) => return support::error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", error.to_string()),
    };
    Json(sanitize::provider(
        &provider,
        &support::base_url(&service),
        &plugin.options().schema.sso_provider.additional_fields,
    ))
    .into_response()
}

pub(super) async fn delete(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<DeleteBody>,
) -> Response {
    let (_, provider) =
        match support::authorized_provider(&service, &plugin, &headers, &body.provider_id).await {
        Ok(authorized) => authorized,
        Err(response) => return *response,
    };
    match guard::delete(&service, &plugin, &provider).await {
        Ok(true) => Json(json!({"success": true})).into_response(),
        Ok(false) | Err(crate::AuthError::SsoStore(SsoStoreError::NotFound)) => not_found(),
        Err(crate::AuthError::SsoProviderMutationRejected) => mutation_rejected(),
        Err(crate::AuthError::SsoStore(error)) => support::storage(error),
        Err(error) => support::error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", error.to_string()),
    }
}

fn not_found() -> Response {
    support::error(StatusCode::NOT_FOUND, "NOT_FOUND", "Provider not found")
}

fn mutation_rejected() -> Response {
    support::error(
        StatusCode::CONFLICT,
        "SSO_PROVIDER_MUTATION_REJECTED",
        "SSO provider mutation is not allowed",
    )
}
