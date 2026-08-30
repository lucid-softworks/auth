use super::super::{auth, DashPlugin};
use crate::{
    AuthError, AuthService, AuthSession, AuthUser, OrganizationPlugin, SessionWithUser,
};
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct OrganizationClaims {
    pub organization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct OrganizationIdsClaims {
    pub organization_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::infra::dash::axum) struct UserClaims {
    pub user_id: String,
    #[serde(default)]
    pub skip_default_team: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InvitationClaims {
    pub organization_id: String,
    pub invitation_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InviterClaims {
    pub organization_id: String,
    pub invited_by: String,
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(in crate::infra::dash::axum) async fn claims<T: serde::de::DeserializeOwned>(
    plugin: &DashPlugin,
    headers: &HeaderMap,
) -> Result<T, Response> {
    auth::regular(plugin, headers).await
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) fn plugin(service: &AuthService) -> Result<&OrganizationPlugin, Response> {
    service.organization_plugin().map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Organization plugin not enabled",
        )
    })
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) fn teams_plugin(service: &AuthService) -> Result<&OrganizationPlugin, Response> {
    let plugin = plugin(service)?;
    if !plugin.config.teams.enabled {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Teams are not enabled",
        ));
    }
    Ok(plugin)
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
pub(super) async fn owner_session(
    service: &AuthService,
    organization_id: &str,
) -> Result<SessionWithUser, Response> {
    let plugin = plugin(service)?;
    let mut owners = plugin
        .store
        .list_members(organization_id)
        .await
        .map_err(route_error)?
        .into_iter()
        .filter(|member| member.role == "owner")
        .collect::<Vec<_>>();
    owners.sort_by_key(|member| member.created_at);
    let owner = owners.first().ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Organization owner not found",
        )
    })?;
    let user = service
        .dash_event_user(&owner.user_id)
        .await
        .map_err(route_error)?
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Organization owner not found",
            )
        })?;
    Ok(synthetic_session(user, None))
}

pub(super) fn synthetic_session(
    user: AuthUser,
    organization_id: Option<&str>,
) -> SessionWithUser {
    let now = Utc::now();
    let mut additional_fields = serde_json::Map::new();
    if let Some(organization_id) = organization_id {
        additional_fields.insert("activeOrganizationId".into(), json!(organization_id));
    }
    SessionWithUser {
        session: AuthSession {
            id: "dash-managed-session".into(),
            user_id: user.id.clone(),
            token: "dash-managed-session".into(),
            actor_user_id: None,
            authentication_method: None,
            expires_at: now + Duration::minutes(5),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
            additional_fields,
        },
        user,
    }
}

pub(in crate::infra::dash::axum) fn route_error(error_value: AuthError) -> Response {
    crate::axum::http::auth_error(error_value)
}

pub(in crate::infra::dash::axum) fn error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response {
    (status, Json(json!({"code": code, "message": message}))).into_response()
}
