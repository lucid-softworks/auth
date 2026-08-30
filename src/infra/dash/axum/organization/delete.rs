use super::support::{
    OrganizationClaims, OrganizationIdsClaims, claims, error, plugin, route_error,
};
use crate::{AuthService, DashPlugin};
use axum::{
    Extension, Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DeleteBody {
    organization_id: String,
}

pub(super) async fn single(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<DeleteBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    if claim.organization_id != body.organization_id {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Organization ID mismatch",
        );
    }
    match service
        .dash_delete_organization(&claim.organization_id)
        .await
    {
        Ok(_) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

pub(super) async fn many(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claim = match claims::<OrganizationIdsClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let mut deleted = Vec::new();
    let mut skipped = Vec::new();
    for id in claim.organization_ids {
        match plugin.store.delete_organization(&id).await {
            Ok(Some(_)) => deleted.push(id),
            Ok(None) | Err(_) => skipped.push(id),
        }
    }
    Json(json!({
        "success": !deleted.is_empty(), "deletedOrgIds": deleted, "skippedOrgIds": skipped
    }))
    .into_response()
}
