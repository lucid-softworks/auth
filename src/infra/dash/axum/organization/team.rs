use super::support::{
    OrganizationClaims, claims, error, owner_session, route_error, teams_plugin,
};
use crate::{AuthService, DashPlugin};
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub(super) struct CreateBody {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateBody {
    team_id: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TeamBody {
    team_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TeamMemberBody {
    team_id: String,
    user_id: String,
}

pub(super) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Response {
    if let Err(response) = claims::<Value>(&dash, &headers).await {
        return response;
    }
    let Ok(plugin) = service.organization_plugin() else {
        return Json(json!([])).into_response();
    };
    if !plugin.config.teams.enabled {
        return Json(json!([])).into_response();
    }
    let teams = match plugin.store.list_teams(&organization_id).await {
        Ok(teams) => teams,
        Err(_) => return Json(json!([])).into_response(),
    };
    let mut output = Vec::new();
    for team in teams {
        let member_count = plugin
            .store
            .list_team_members(&team.id)
            .await
            .map_or(0, |members| members.len());
        let mut value = serde_json::to_value(team).expect("team serializes");
        value
            .as_object_mut()
            .expect("team is an object")
            .insert("memberCount".into(), json!(member_count));
        output.push(value);
    }
    Json(output).into_response()
}

pub(super) async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<CreateBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    if let Err(response) = teams_plugin(&service) {
        return response;
    }
    let session = match owner_session(&service, &claim.organization_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match service
        .create_organization_team(&session, Some(claim.organization_id), body.name)
        .await
    {
        Ok(team) => Json(team).into_response(),
        Err(error) => route_error(error),
    }
}

pub(super) async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<UpdateBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match teams_plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    if !team_belongs(plugin, &body.team_id, &claim.organization_id).await {
        return team_not_found();
    }
    let session = match owner_session(&service, &claim.organization_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match service
        .update_organization_team(&session, body.team_id, body.name)
        .await
    {
        Ok(team) => Json(team).into_response(),
        Err(error) => route_error(error),
    }
}

pub(super) async fn delete(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<TeamBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match teams_plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    if !team_belongs(plugin, &body.team_id, &claim.organization_id).await {
        return team_not_found();
    }
    let session = match owner_session(&service, &claim.organization_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match service
        .remove_organization_team(&session, Some(claim.organization_id), body.team_id)
        .await
    {
        Ok(()) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

pub(super) async fn list_members(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path((organization_id, team_id)): Path<(String, String)>,
) -> Response {
    if let Err(response) = claims::<Value>(&dash, &headers).await {
        return response;
    }
    let Ok(plugin) = service.organization_plugin() else {
        return Json(json!([])).into_response();
    };
    if !plugin.config.teams.enabled
        || !team_belongs(plugin, &team_id, &organization_id).await
    {
        return Json(json!([])).into_response();
    }
    let members = match plugin.store.list_team_members(&team_id).await {
        Ok(members) => members,
        Err(_) => return Json(json!([])).into_response(),
    };
    let mut output = Vec::new();
    for member in members {
        let user = service.dash_event_user(&member.user_id).await.ok().flatten();
        let mut value = serde_json::to_value(member).expect("team member serializes");
        value.as_object_mut().expect("team member is an object").insert(
            "user".into(),
            user.map_or(Value::Null, |user| {
                json!({"id": user.id, "name": user.name, "email": user.email, "image": user.image})
            }),
        );
        output.push(value);
    }
    Json(output).into_response()
}

pub(super) async fn add_member(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<TeamMemberBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match teams_plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    if !team_belongs(plugin, &body.team_id, &claim.organization_id).await {
        return team_not_found();
    }
    if plugin
        .store
        .list_team_members(&body.team_id)
        .await
        .is_ok_and(|members| members.iter().any(|member| member.user_id == body.user_id))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "User is already a member of this team",
        );
    }
    let session = match owner_session(&service, &claim.organization_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match service
        .add_organization_team_member(
            &session,
            Some(claim.organization_id),
            body.team_id,
            body.user_id,
        )
        .await
    {
        Ok(member) => Json(member).into_response(),
        Err(error) => route_error(error),
    }
}

pub(super) async fn remove_member(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<TeamMemberBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match teams_plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    if !team_belongs(plugin, &body.team_id, &claim.organization_id).await {
        return team_not_found();
    }
    let session = match owner_session(&service, &claim.organization_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match service
        .remove_organization_team_member(
            &session,
            Some(claim.organization_id),
            body.team_id,
            body.user_id,
        )
        .await
    {
        Ok(()) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

async fn team_belongs(
    plugin: &crate::OrganizationPlugin,
    team_id: &str,
    organization_id: &str,
) -> bool {
    plugin
        .store
        .find_team(team_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|team| team.organization_id == organization_id)
}

fn team_not_found() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "Team not found or does not belong to this organization",
    )
}

