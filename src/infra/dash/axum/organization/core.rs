use super::support::{
    OrganizationClaims, UserClaims, claims, error, owner_session, plugin, route_error,
    synthetic_session,
};
use crate::{
    AuthService, DashPlugin, DashSortDirection, NewOrganization, OrganizationUpdate,
};
use axum::{
    Extension, Json,
    body::Body,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ListQuery {
    limit: Option<f64>,
    offset: Option<f64>,
    sort_by: Option<String>,
    sort_order: Option<DashSortDirection>,
    filter_members: Option<String>,
    search: Option<String>,
    start_date: Option<DateTime<Utc>>,
    end_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExportQuery {
    limit: Option<f64>,
    offset: Option<f64>,
    sort_by: Option<String>,
    sort_order: Option<DashSortDirection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateBody {
    name: String,
    slug: String,
    logo: Option<String>,
    default_team_name: Option<String>,
    #[serde(flatten)]
    _additional: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateBody {
    name: Option<String>,
    slug: Option<String>,
    logo: Option<String>,
    metadata: Option<String>,
    #[serde(flatten)]
    _additional: Map<String, Value>,
}

pub(super) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if let Err(response) = claims::<Value>(&dash, &headers).await {
        return response;
    }
    let Ok(plugin) = service.organization_plugin() else {
        return Json(json!({
            "organizations": [], "total": 0,
            "offset": query.offset.unwrap_or(0.0), "limit": query.limit.unwrap_or(10.0)
        }))
        .into_response();
    };
    let mut organizations = match plugin.store.list_all_organizations().await {
        Ok(organizations) => organizations,
        Err(error) => return route_error(error),
    };
    if let Some(search) = query.search.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        let search = search.to_lowercase();
        organizations.retain(|organization| {
            organization.name.to_lowercase().starts_with(&search)
                || organization.slug.to_lowercase().starts_with(&search)
        });
    }
    if let Some(start) = query.start_date {
        organizations.retain(|organization| organization.created_at >= start);
    }
    if let Some(end) = query.end_date {
        organizations.retain(|organization| organization.created_at <= end);
    }
    let mut projected = Vec::with_capacity(organizations.len());
    for organization in organizations {
        let members = match plugin.store.list_members(&organization.id).await {
            Ok(members) => members,
            Err(error) => return route_error(error),
        };
        let count = members.len();
        if !matches_member_filter(query.filter_members.as_deref(), count) {
            continue;
        }
        let mut previews = Vec::new();
        for member in members.into_iter().take(5) {
            if let Ok(Some(user)) = service.dash_event_user(&member.user_id).await {
                previews.push(json!({
                    "id": user.id, "name": user.name, "email": user.email, "image": user.image
                }));
            }
        }
        projected.push((organization, count, previews));
    }
    sort_organizations(&mut projected, query.sort_by.as_deref(), query.sort_order);
    let total = projected.len();
    let offset = index(query.offset, 0.0);
    let limit = index(query.limit, 10.0);
    let organizations = projected
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(organization, member_count, members)| {
            let mut value = serde_json::to_value(organization).expect("organization serializes");
            let object = value.as_object_mut().expect("organization is an object");
            object.insert("memberCount".into(), json!(member_count));
            object.insert("members".into(), json!(members));
            value
        })
        .collect::<Vec<_>>();
    Json(json!({
        "organizations": organizations, "total": total,
        "offset": query.offset.unwrap_or(0.0), "limit": query.limit.unwrap_or(10.0)
    }))
    .into_response()
}

pub(super) async fn export(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Response {
    if let Err(response) = claims::<Value>(&dash, &headers).await {
        return response;
    }
    let plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let mut organizations = match plugin.store.list_all_organizations().await {
        Ok(organizations) => organizations,
        Err(error) => return route_error(error),
    };
    let descending = query.sort_order.unwrap_or(DashSortDirection::Desc) == DashSortDirection::Desc;
    organizations.sort_by(|left, right| {
        let ordering = match query.sort_by.as_deref().unwrap_or("createdAt") {
            "name" => left.name.cmp(&right.name),
            "slug" => left.slug.cmp(&right.slug),
            _ => left.created_at.cmp(&right.created_at),
        };
        if descending { ordering.reverse() } else { ordering }
    });
    let body = organizations
        .into_iter()
        .skip(index(query.offset, 0.0))
        .take(query.limit.map_or(usize::MAX, |limit| index(Some(limit), 0.0)))
        .map(|organization| serde_json::to_string(&organization).expect("organization serializes"))
        .collect::<Vec<_>>()
        .join("\n");
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from(if body.is_empty() { body } else { format!("{body}\n") }),
    )
        .into_response()
}

pub(super) async fn options(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = claims::<Value>(&dash, &headers).await {
        return response;
    }
    let teams_enabled = service
        .organization_plugin()
        .is_ok_and(|plugin| plugin.config.teams.enabled && plugin.config.teams.default_team_enabled);
    Json(json!({"teamsEnabled": teams_enabled})).into_response()
}

pub(super) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = claims::<Value>(&dash, &headers).await {
        return response;
    }
    let plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let organization = match plugin.store.find_organization_by_id(&id).await {
        Ok(Some(organization)) => organization,
        Ok(None) => return error(StatusCode::NOT_FOUND, "NOT_FOUND", "Organization not found"),
        Err(error) => return route_error(error),
    };
    let member_count = match plugin.store.list_members(&id).await {
        Ok(members) => members.len(),
        Err(error) => return route_error(error),
    };
    let mut value = serde_json::to_value(organization).expect("organization serializes");
    value
        .as_object_mut()
        .expect("organization is an object")
        .insert("memberCount".into(), json!(member_count));
    Json(value).into_response()
}

pub(super) async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<CreateBody>,
) -> Response {
    let claim = match claims::<UserClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    if body.name.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Too small: expected string to have >=1 characters",
        );
    }
    if let Some(message) = slug_error(&body.slug) {
        return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message);
    }
    if let Err(response) = plugin(&service) {
        return response;
    }
    let user = match service.dash_event_user(&claim.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "User not found"),
        Err(error) => return route_error(error),
    };
    let session = synthetic_session(user, None);
    match service
        .create_dash_organization(
            &session,
            NewOrganization {
                name: body.name,
                slug: body.slug,
                logo: body.logo,
                metadata: None,
                keep_current_active_organization: true,
            },
            body.default_team_name,
            claim.skip_default_team,
        )
        .await
    {
        Ok(created) => Json(json!({
            "id": created.organization.id,
            "name": created.organization.name,
            "slug": created.organization.slug,
            "logo": created.organization.logo,
            "metadata": created.organization.metadata,
            "createdAt": created.organization.created_at,
            "members": [created.member]
        }))
        .into_response(),
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
    if body.name.is_none() && body.slug.is_none() && body.logo.is_none() && body.metadata.is_none() {
        return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "No valid fields to update");
    }
    if body.name.as_deref() == Some("") {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Too small: expected string to have >=1 characters",
        );
    }
    if let Some(message) = body.slug.as_deref().and_then(slug_error) {
        return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message);
    }
    if body.logo.as_deref().is_some_and(invalid_safe_url) {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "URL must be a valid http(s) URL without credentials",
        );
    }
    let metadata = match body.metadata {
        Some(value) if value.is_empty() => None,
        Some(value) => match serde_json::from_str(&value) {
            Ok(value) => Some(value),
            Err(_) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid metadata: must be valid JSON"),
        },
        None => None,
    };
    let session = match owner_session(&service, &claim.organization_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match service
        .update_organization(
            &session,
            Some(claim.organization_id),
            OrganizationUpdate {
                name: body.name,
                slug: body.slug,
                logo: body.logo.map(|logo| (!logo.is_empty()).then_some(logo)),
                metadata,
            },
        )
        .await
    {
        Ok(organization) => Json(organization).into_response(),
        Err(error) => route_error(error),
    }
}

fn index(value: Option<f64>, fallback: f64) -> usize {
    value
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or(fallback)
        .floor()
        .min(usize::MAX as f64) as usize
}

fn slug_error(slug: &str) -> Option<&'static str> {
    if slug.is_empty() {
        return Some("Slug is required");
    }
    (!slug
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    .then_some("Slug can only contain lowercase letters, numbers, and hyphens")
}

fn invalid_safe_url(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    url::Url::parse(value).map_or(true, |url| {
        !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
    })
}

fn matches_member_filter(filter: Option<&str>, count: usize) -> bool {
    match filter {
        Some("abandoned") => count == 0,
        Some("eq1") => count == 1,
        Some("gt1") => count > 1,
        Some("gt5") => count > 5,
        Some("gt10") => count > 10,
        _ => true,
    }
}

fn sort_organizations(
    organizations: &mut [(crate::Organization, usize, Vec<Value>)],
    field: Option<&str>,
    direction: Option<DashSortDirection>,
) {
    organizations.sort_by(|left, right| {
        let ordering = match field.unwrap_or("createdAt") {
            "name" => left.0.name.cmp(&right.0.name),
            "slug" => left.0.slug.cmp(&right.0.slug),
            "members" => left.1.cmp(&right.1),
            _ => left.0.created_at.cmp(&right.0.created_at),
        };
        if direction.unwrap_or(DashSortDirection::Desc) == DashSortDirection::Desc {
            ordering.reverse()
        } else {
            ordering
        }
        .then_with(|| left.0.id.cmp(&right.0.id))
    });
}
