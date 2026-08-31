use super::super::support::{claims, error, plugin as organization_plugin, route_error};
use crate::{AuthService, DashPlugin, ScimPlugin};
use axum::{http::{HeaderMap, StatusCode}, response::Response};
use serde::Deserialize;

const SETUP_ID_MIN_LENGTH: usize = 16;
const SETUP_ID_MAX_LENGTH: usize = 255;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectoryClaims {
    purpose: String,
    organization_id: String,
    pub actor_id: String,
    pub setup_operation_id: Option<String>,
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) async fn authorize<'a>(
    service: &'a AuthService,
    dash: &DashPlugin,
    headers: &HeaderMap,
    organization_id: &str,
    allow_setup: bool,
) -> Result<(&'a ScimPlugin, DirectoryClaims), Response> {
    organization_plugin(service)?;
    let claims = claims::<DirectoryClaims>(dash, headers).await?;
    if !claims.valid_for(organization_id) {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid directory sync management authorization",
        ));
    }
    if !allow_setup && claims.setup_operation_id.is_some() {
        return Err(error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Directory sync setup authorization cannot perform management operations",
        ));
    }
    let organization = service
        .organization_plugin()
        .expect("organization plugin checked")
        .store
        .find_organization_by_id(organization_id)
        .await
        .map_err(route_error)?;
    if organization.is_none() {
        return Err(error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Target organization not found",
        ));
    }
    if !dash.options().managed_directory_sync.enabled {
        return Err(disabled());
    }
    let scim = service.scim_plugin().ok_or_else(disabled)?;
    if scim.options().managed_connections.is_none() {
        return Err(disabled());
    }
    Ok((scim, claims))
}

pub(super) fn managed_mode(service: &AuthService, dash: &DashPlugin) -> bool {
    dash.options().managed_directory_sync.enabled
        && service
            .scim_plugin()
            .is_some_and(|scim| scim.options().managed_connections.is_some())
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) async fn unconstrained(
    dash: &DashPlugin,
    headers: &HeaderMap,
) -> Result<(), Response> {
    claims::<serde_json::Value>(dash, headers).await.map(|_| ())
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) async fn legacy(
    service: &AuthService,
    dash: &DashPlugin,
    headers: &HeaderMap,
) -> Result<(), Response> {
    organization_plugin(service)?;
    let claims = claims::<super::super::support::OrganizationClaims>(dash, headers).await?;
    if claims.organization_id.trim().is_empty() {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid organization authorization",
        ));
    }
    Ok(())
}

impl DirectoryClaims {
    fn valid_for(&self, organization_id: &str) -> bool {
        self.purpose == "directory-sync-management"
            && self.organization_id.trim() == organization_id
            && !self.organization_id.trim().is_empty()
            && !self.actor_id.trim().is_empty()
            && self.setup_operation_id.as_deref().is_none_or(valid_setup_id)
    }
}

fn valid_setup_id(value: &str) -> bool {
    let length = value.trim().len();
    (SETUP_ID_MIN_LENGTH..=SETUP_ID_MAX_LENGTH).contains(&length)
}

fn disabled() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "Managed directory sync is disabled. Enable dash({ managedDirectorySync: { enabled: true } }) and migrate the directory sync schema. Legacy SCIM directory sync does not use this option.",
    )
}
