mod config;

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
    let prepared = match config::prepare(&service, &plugin, &provider, &body) {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let provider = match plugin
        .store()
        .update_guarded(
            &provider.id,
            &provider.provider_id,
            prepared.update,
            prepared.identity_boundary_changed,
        )
        .await
    {
        Ok(provider) => provider,
        Err(SsoStoreError::LinkedAccounts) => {
            return support::error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Cannot change SSO provider identity fields while linked accounts exist",
            );
        }
        Err(SsoStoreError::NotFound) => return not_found(),
        Err(error) => return support::storage(error),
    };
    Json(sanitize::provider(&provider, &support::base_url(&service))).into_response()
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
    match plugin
        .store()
        .delete_with_accounts(&provider.id, &provider.provider_id)
        .await
    {
        Ok(true) => Json(json!({"success": true})).into_response(),
        Ok(false) | Err(SsoStoreError::NotFound) => not_found(),
        Err(error) => support::storage(error),
    }
}

fn not_found() -> Response {
    support::error(StatusCode::NOT_FOUND, "NOT_FOUND", "Provider not found")
}
