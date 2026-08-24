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
use serde_json::Value;
use std::sync::Arc;

pub(super) fn routes() -> Vec<AxumPluginRoute> {
    vec![
        route_post("/organization/create-team", create),
        route_get("/organization/list-teams", list),
        route_post("/organization/remove-team", remove),
        route_post("/organization/update-team", update),
        route_post("/organization/set-active-team", set_active),
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRequest {
    name: String,
    organization_id: Option<String>,
}

async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<CreateRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match optional_id(input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .create_organization_team(&session, organization_id, input.name)
        .await
    {
        Ok(team) => Json(team).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationQuery {
    organization_id: Option<String>,
}

async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<OrganizationQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match optional_id(query.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .list_organization_teams(&session, organization_id)
        .await
    {
        Ok(teams) => Json(teams).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamRequest {
    team_id: String,
    organization_id: Option<String>,
}

async fn remove(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<TeamRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let team_id = match id(&input.team_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let organization_id = match optional_id(input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .remove_organization_team(&session, organization_id, team_id)
        .await
    {
        Ok(()) => {
            Json(serde_json::json!({ "message": "Team removed successfully." })).into_response()
        }
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateRequest {
    team_id: String,
    data: UpdateData,
}

#[derive(Deserialize)]
struct UpdateData {
    name: Option<String>,
}

async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdateRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let team_id = match id(&input.team_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .update_organization_team(&session, team_id, input.data.name)
        .await
    {
        Ok(team) => Json(team).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetActiveRequest {
    team_id: Option<Value>,
}

async fn set_active(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<SetActiveRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let team_id = match input.team_id {
        Some(Value::String(value)) => match id(&value) {
            Ok(id) => Some(id),
            Err(error) => return auth_error(error),
        },
        Some(Value::Null) => None,
        Some(_) => {
            return auth_error(AuthError::InvalidRequest(
                "teamId must be a string or null".into(),
            ));
        }
        None => AuthService::active_team_id(&session),
    };
    match service
        .set_active_organization_team(&session, team_id)
        .await
    {
        Ok(team) => Json(team).into_response(),
        Err(error) => auth_error(error),
    }
}
