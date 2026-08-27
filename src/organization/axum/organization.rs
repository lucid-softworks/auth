use crate::{
    AuthError, AuthService, AxumPluginRoute, NewOrganization, OrganizationError,
    OrganizationUpdate,
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
use serde_json::Value;
use std::sync::Arc;

pub(super) fn routes() -> Vec<AxumPluginRoute> {
    vec![
        route_post("/organization/create", create),
        route_post("/organization/update", update),
        route_post("/organization/delete", delete),
        route_post("/organization/set-active", set_active),
        route_get("/organization/get-organization", get_organization),
        route_get("/organization/get-full-organization", get_full_organization),
        route_get("/organization/list", list),
        route_post("/organization/check-slug", check_slug),
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
    slug: String,
    logo: Option<String>,
    metadata: Option<Value>,
    keep_current_active_organization: Option<bool>,
}

#[derive(Serialize)]
struct CreateResponse {
    #[serde(flatten)]
    organization: crate::Organization,
    members: Vec<crate::OrganizationMember>,
}

async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<CreateRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    if input.name.is_empty() || input.slug.is_empty() {
        return auth_error(AuthError::InvalidRequest(
            "organization name and slug are required".into(),
        ));
    }
    match service
        .create_organization(
            &session,
            NewOrganization {
                name: input.name,
                slug: input.slug,
                logo: input.logo,
                metadata: input.metadata,
                keep_current_active_organization: input
                    .keep_current_active_organization
                    .unwrap_or(false),
            },
        )
        .await
    {
        Ok(created) => Json(CreateResponse {
            organization: created.organization,
            members: vec![created.member],
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateRequest {
    organization_id: Option<String>,
    data: UpdateData,
}

#[derive(Deserialize)]
struct UpdateData {
    name: Option<String>,
    slug: Option<String>,
    logo: Option<Value>,
    metadata: Option<Value>,
}

async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdateRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match optional_id(input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let logo = match input.data.logo {
        Some(Value::Null) => Some(None),
        Some(Value::String(value)) => Some(Some(value)),
        Some(_) => {
            return auth_error(AuthError::InvalidRequest(
                "organization logo must be a string or null".into(),
            ));
        }
        None => None,
    };
    match service
        .update_organization(
            &session,
            organization_id,
            OrganizationUpdate {
                name: input.data.name,
                slug: input.data.slug,
                logo,
                metadata: input.data.metadata,
            },
        )
        .await
    {
        Ok(organization) => Json(organization).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRequest {
    organization_id: String,
}

async fn delete(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<DeleteRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match id(&input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service.delete_organization(&session, organization_id).await {
        Ok(organization) => Json(organization).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationQuery {
    organization_id: Option<String>,
    organization_slug: Option<String>,
    members_limit: Option<usize>,
}

async fn get_organization(
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
        .get_organization(
            &session,
            organization_id,
            query.organization_slug.as_deref(),
        )
        .await
    {
        Ok(organization) => Json(organization).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn get_full_organization(
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
        .get_full_organization(
            &session,
            organization_id,
            query.organization_slug.as_deref(),
            query.members_limit,
        )
        .await
    {
        Ok(Some(organization)) => {
            let mut members = Vec::with_capacity(organization.members.len());
            for entry in organization.members {
                let user = match service.better_auth_user(&entry.user).await {
                    Ok(user) => user,
                    Err(error) => return auth_error(error),
                };
                members.push(FullMemberResponse {
                    member: entry.member,
                    user,
                });
            }
            Json(Some(FullOrganizationResponse {
                organization: organization.organization,
                members,
                invitations: organization.invitations,
                teams: organization.teams,
            }))
            .into_response()
        }
        Ok(None) => Json(Option::<FullOrganizationResponse>::None).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FullMemberResponse {
    #[serde(flatten)]
    member: crate::OrganizationMember,
    user: crate::protocol::better_auth::BetterAuthUser,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FullOrganizationResponse {
    #[serde(flatten)]
    organization: crate::Organization,
    members: Vec<FullMemberResponse>,
    invitations: Vec<crate::OrganizationInvitation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    teams: Option<Vec<crate::OrganizationTeam>>,
}

async fn list(Extension(service): Extension<Arc<AuthService>>, headers: HeaderMap) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service.list_organizations(&session).await {
        Ok(organizations) => Json(organizations).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
struct SlugRequest {
    slug: String,
}

async fn check_slug(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<SlugRequest>,
) -> Response {
    if current_session(&service, &headers).await.is_none() {
        return auth_error(AuthError::Unauthorized);
    }
    match service.organization_plugin() {
        Ok(plugin) => match plugin.store.find_organization_by_slug(&input.slug).await {
            Ok(None) => Json(serde_json::json!({ "status": true })).into_response(),
            Ok(Some(_)) => auth_error(
                OrganizationError::bad_request(
                    "ORGANIZATION_SLUG_ALREADY_TAKEN",
                    "Organization slug already taken",
                )
                .into(),
            ),
            Err(error) => auth_error(error),
        },
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetActiveRequest {
    organization_id: Option<Value>,
    organization_slug: Option<String>,
}

async fn set_active(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<SetActiveRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    if input.organization_id == Some(Value::Null) {
        return match service.set_active_organization(&session, None).await {
            Ok(_) => Json(Value::Null).into_response(),
            Err(error) => auth_error(error),
        };
    }
    let explicit = match input.organization_id {
        Some(Value::String(value)) => match id(&value) {
            Ok(id) => Some(id),
            Err(error) => return auth_error(error),
        },
        Some(_) => {
            return auth_error(AuthError::InvalidRequest(
                "organizationId must be a string or null".into(),
            ));
        }
        None => None,
    };
    let selected = match service
        .get_organization(&session, explicit, input.organization_slug.as_deref())
        .await
    {
        Ok(organization) => organization,
        Err(error) => return auth_error(error),
    };
    let Some(organization) = selected else {
        return Json(Value::Null).into_response();
    };
    match service
        .set_active_organization(&session, Some(organization.id.clone()))
        .await
    {
        Ok(_) => Json(organization).into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) fn optional_id(value: Option<String>) -> Result<Option<String>, AuthError> {
    value.map(|value| id(&value)).transpose()
}

pub(super) fn id(value: &str) -> Result<String, AuthError> {
    (!value.is_empty())
        .then(|| value.to_owned())
        .ok_or_else(|| {
            OrganizationError::bad_request("ORGANIZATION_NOT_FOUND", "Organization not found")
                .into()
        })
}
