use super::organization::{id, optional_id};
use crate::{
    AuthError, AuthService, AxumPluginRoute, OrganizationPermissions,
    axum::http::{auth_error, current_session},
    protocol::better_auth::BetterAuthUser,
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
        route_get("/organization/get-active-member", get_active),
        route_post("/organization/remove-member", remove),
        route_post("/organization/update-member-role", update_role),
        route_post("/organization/leave", leave),
        route_get("/organization/list-members", list),
        route_get("/organization/get-active-member-role", get_active_role),
        route_post("/organization/has-permission", has_permission),
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

async fn get_active(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service.active_organization_member(&session).await {
        Ok(member) => Json(member).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveRequest {
    member_id_or_email: String,
    organization_id: Option<String>,
}

#[derive(Serialize)]
struct RemoveResponse {
    member: crate::OrganizationMember,
}

async fn remove(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<RemoveRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match optional_id(input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .remove_organization_member(&session, organization_id, &input.member_id_or_email)
        .await
    {
        Ok(member) => Json(RemoveResponse { member }).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateRoleRequest {
    member_id: String,
    organization_id: Option<String>,
    role: RoleInput,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    fn into_string(self) -> String {
        match self {
            Self::One(role) => role,
            Self::Many(roles) => roles.join(","),
        }
    }
}

async fn update_role(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdateRoleRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let member_id = match id(&input.member_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let organization_id = match optional_id(input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .update_organization_member_role(
            &session,
            organization_id,
            member_id,
            input.role.into_string(),
        )
        .await
    {
        Ok(member) => Json(member).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeaveRequest {
    organization_id: String,
}

async fn leave(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<LeaveRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match id(&input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service.leave_organization(&session, organization_id).await {
        Ok(member) => Json(member).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Serialize)]
struct MemberResponse {
    #[serde(flatten)]
    member: crate::OrganizationMember,
    user: BetterAuthUser,
}

#[derive(Serialize)]
struct ListResponse {
    members: Vec<MemberResponse>,
    total: usize,
}

async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<super::member_list::MemberQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match resolve_organization_id(&service, &session, &query).await {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let mut members = match service
        .list_organization_members_with_users(&session, organization_id)
        .await
    {
        Ok(members) => members,
        Err(error) => return auth_error(error),
    };
    if let Err(error) = super::member_list::apply(&mut members, &query) {
        return auth_error(error);
    }
    let total = members.len();
    let mut output = Vec::new();
    for entry in members
        .into_iter()
        .skip(query.offset.unwrap_or(0))
        .take(query.limit.unwrap_or(100))
    {
        match service.better_auth_user(&entry.user).await {
            Ok(user) => output.push(MemberResponse {
                member: entry.member,
                user,
            }),
            Err(error) => return auth_error(error),
        }
    }
    Json(ListResponse {
        members: output,
        total,
    })
    .into_response()
}

#[derive(Serialize)]
struct RoleResponse {
    role: String,
}

async fn get_active_role(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<super::member_list::MemberQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match resolve_organization_id(&service, &session, &query).await {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let user_id = match optional_id(query.user_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .organization_member_role(&session, organization_id, user_id)
        .await
    {
        Ok(role) => Json(RoleResponse { role }).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PermissionRequest {
    organization_id: Option<String>,
    permissions: Option<OrganizationPermissions>,
    permission: Option<OrganizationPermissions>,
}

async fn has_permission(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<PermissionRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match optional_id(input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let Some(permissions) = input.permissions.or(input.permission) else {
        return auth_error(AuthError::InvalidRequest("permissions are required".into()));
    };
    match service
        .has_organization_permission(&session, organization_id, permissions)
        .await
    {
        Ok(success) => {
            Json(serde_json::json!({ "error": null, "success": success })).into_response()
        }
        Err(error) => auth_error(error),
    }
}

async fn resolve_organization_id(
    service: &AuthService,
    session: &crate::SessionWithUser,
    query: &super::member_list::MemberQuery,
) -> Result<Option<Uuid>, AuthError> {
    if let Some(slug) = query.organization_slug.as_deref() {
        return service
            .get_organization(session, None, Some(slug))
            .await
            .map(|organization| organization.map(|organization| organization.id));
    }
    optional_id(query.organization_id.clone())
}
