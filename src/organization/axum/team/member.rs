use super::super::organization::{id, optional_id};
use crate::{
    AuthError, AuthService, AxumPluginRoute,
    axum::http::{auth_error, current_session},
};
use axum::{
    Extension, Json,
    extract::Query,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;

pub(super) fn routes() -> Vec<AxumPluginRoute> {
    vec![
        route_get("/organization/list-user-teams", list_user_teams),
        route_get("/organization/list-team-members", list_team_members),
        route_post("/organization/add-team-member", add_member),
        route_post("/organization/remove-team-member", remove_member),
    ]
}

fn route_post<H, T>(path: &'static str, handler: H) -> AxumPluginRoute
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    AxumPluginRoute::new(path, post(handler))
}

fn route_get<H, T>(path: &'static str, handler: H) -> AxumPluginRoute
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    AxumPluginRoute::new(path, get(handler))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserTeamsQuery {
    user_id: Option<String>,
    organization_id: Option<String>,
}

async fn list_user_teams(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<UserTeamsQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let user_id = match optional_id(query.user_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let organization_id = match optional_id(query.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .list_user_organization_teams(&session, user_id, organization_id)
        .await
    {
        Ok(teams) => Json(teams).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamQuery {
    team_id: Option<String>,
}

async fn list_team_members(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<TeamQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let team_id = match optional_id(query.team_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .list_organization_team_members(&session, team_id)
        .await
    {
        Ok(members) => Json(members).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamMemberRequest {
    team_id: String,
    user_id: String,
    organization_id: Option<String>,
}

async fn add_member(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<TeamMemberRequest>,
) -> Response {
    mutate_member(&service, &headers, input, true).await
}

async fn remove_member(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<TeamMemberRequest>,
) -> Response {
    mutate_member(&service, &headers, input, false).await
}

async fn mutate_member(
    service: &AuthService,
    headers: &HeaderMap,
    input: TeamMemberRequest,
    add: bool,
) -> Response {
    let Some(session) = current_session(service, headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let team_id = match id(&input.team_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let user_id = match id(&input.user_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let organization_id = match optional_id(input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    if add {
        match service
            .add_organization_team_member(&session, organization_id, team_id, user_id)
            .await
        {
            Ok(member) => Json(member).into_response(),
            Err(error) => auth_error(error),
        }
    } else {
        match service
            .remove_organization_team_member(&session, organization_id, team_id, user_id)
            .await
        {
            Ok(()) => Json(serde_json::json!({
                "message": "Team member removed successfully."
            }))
            .into_response(),
            Err(error) => auth_error(error),
        }
    }
}
