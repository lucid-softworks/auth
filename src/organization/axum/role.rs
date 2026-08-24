use super::organization::{id, optional_id};
use crate::{
    AuthError, AuthService, AxumPluginRoute, OrganizationPermissions, OrganizationRole,
    axum::http::{auth_error, current_session},
};
use axum::{
    Extension, Json,
    extract::Query,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn routes() -> Vec<AxumPluginRoute> {
    vec![
        route_post("/organization/create-role", create),
        route_post("/organization/delete-role", delete),
        route_get("/organization/list-roles", list),
        route_get("/organization/get-role", get_role),
        route_post("/organization/update-role", update),
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
    organization_id: Option<String>,
    role: String,
    permission: OrganizationPermissions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoleMutationResponse {
    success: bool,
    role_data: OrganizationRole,
    statements: OrganizationPermissions,
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
        .create_organization_role(&session, organization_id, input.role, input.permission)
        .await
    {
        Ok(role) => role_response(role),
        Err(error) => auth_error(error),
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleSelector {
    organization_id: Option<String>,
    role_id: Option<String>,
    role_name: Option<String>,
}

async fn delete(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<RoleSelector>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let (organization_id, role_id) = match selector_ids(&input) {
        Ok(ids) => ids,
        Err(error) => return auth_error(error),
    };
    match service
        .delete_organization_role(
            &session,
            organization_id,
            role_id,
            input.role_name.as_deref(),
        )
        .await
    {
        Ok(()) => Json(serde_json::json!({ "success": true })).into_response(),
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
        .list_organization_roles(&session, organization_id)
        .await
    {
        Ok(roles) => Json(roles).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn get_role(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<RoleSelector>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let (organization_id, role_id) = match selector_ids(&query) {
        Ok(ids) => ids,
        Err(error) => return auth_error(error),
    };
    match service
        .get_organization_role(
            &session,
            organization_id,
            role_id,
            query.role_name.as_deref(),
        )
        .await
    {
        Ok(role) => Json(role).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateRequest {
    organization_id: Option<String>,
    role_id: Option<String>,
    role_name: Option<String>,
    data: UpdateData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateData {
    permission: Option<OrganizationPermissions>,
    role_name: Option<String>,
}

async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdateRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let selector = RoleSelector {
        organization_id: input.organization_id,
        role_id: input.role_id,
        role_name: input.role_name,
    };
    let (organization_id, role_id) = match selector_ids(&selector) {
        Ok(ids) => ids,
        Err(error) => return auth_error(error),
    };
    match service
        .update_organization_role(
            &session,
            organization_id,
            role_id,
            selector.role_name.as_deref(),
            input.data.role_name,
            input.data.permission,
        )
        .await
    {
        Ok(role) => role_response(role),
        Err(error) => auth_error(error),
    }
}

fn selector_ids(selector: &RoleSelector) -> Result<(Option<Uuid>, Option<Uuid>), AuthError> {
    if selector.role_id.is_none() && selector.role_name.is_none() {
        return Err(
            crate::OrganizationError::bad_request("ROLE_NOT_FOUND", "Role not found").into(),
        );
    }
    Ok((
        optional_id(selector.organization_id.clone())?,
        selector.role_id.as_deref().map(id).transpose()?,
    ))
}

fn role_response(role: OrganizationRole) -> Response {
    let statements = role.permission.clone();
    Json(RoleMutationResponse {
        success: true,
        role_data: role,
        statements,
    })
    .into_response()
}
