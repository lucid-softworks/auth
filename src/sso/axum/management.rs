use super::{sanitize, support};
use crate::{AuthService, SsoPlugin};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GetQuery {
    provider_id: String,
}

pub(super) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    headers: HeaderMap,
) -> Response {
    let session = match support::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let providers = match plugin.store().list().await {
        Ok(providers) => providers,
        Err(error) => return support::storage(error),
    };
    let base_url = support::base_url(&service);
    let mut accessible = Vec::new();
    for provider in providers {
        if support::has_access(&service, &provider, &session.user.id).await {
            accessible.push(sanitize::provider(
                &provider,
                &base_url,
                &plugin.options().schema.sso_provider.additional_fields,
            ));
        }
    }
    Json(json!({"providers": accessible})).into_response()
}

pub(super) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    headers: HeaderMap,
    Query(query): Query<GetQuery>,
) -> Response {
    let session = match support::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let provider = match plugin
        .store()
        .find_by_provider_id(&query.provider_id)
        .await
    {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return support::error(StatusCode::NOT_FOUND, "NOT_FOUND", "Provider not found");
        }
        Err(error) => return support::storage(error),
    };
    if !support::has_access(&service, &provider, &session.user.id).await {
        return support::error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "You don't have access to this provider",
        );
    }
    Json(sanitize::provider(
        &provider,
        &support::base_url(&service),
        &plugin.options().schema.sso_provider.additional_fields,
    ))
    .into_response()
}
