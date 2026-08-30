use super::support::{OrganizationClaims, claims, plugin, route_error};
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
#[serde(rename_all = "camelCase")]
pub(super) struct AddBody {
    user_id: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MemberBody {
    member_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RoleBody {
    member_id: String,
    role: String,
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
    let members = match plugin.store.list_members(&organization_id).await {
        Ok(members) => members,
        Err(error) => return route_error(error),
    };
    let invitations = plugin
        .store
        .list_invitations(&organization_id)
        .await
        .unwrap_or_default();
    let mut output = Vec::new();
    for member in members {
        let user = match service.dash_event_user(&member.user_id).await {
            Ok(Some(user)) => user,
            _ => continue,
        };
        let inviter_id = invitations
            .iter()
            .find(|invitation| {
                invitation.status == crate::OrganizationInvitationStatus::Accepted
                    && invitation.email.eq_ignore_ascii_case(&user.email)
            })
            .map(|invitation| invitation.inviter_id.clone());
        let invited_by = match inviter_id {
            Some(inviter_id) => service
                .dash_event_user(&inviter_id)
                .await
                .ok()
                .flatten()
                .map(|inviter| preview(&inviter)),
            None => None,
        };
        let mut value = serde_json::to_value(&member).expect("member serializes");
        let object = value.as_object_mut().expect("member is an object");
        object.insert("user".into(), preview(&user));
        object.insert("invitedBy".into(), invited_by.unwrap_or(Value::Null));
        output.push(value);
    }
    Json(output).into_response()
}

pub(super) async fn add(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<AddBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let organization_plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let role = body.role.trim().to_owned();
    if !valid_role(&role) || !organization_plugin.config.roles.contains_key(&role) {
        return invalid_role(organization_plugin);
    }
    match service
        .dash_add_organization_member(&claim.organization_id, &body.user_id, role)
        .await
    {
        Ok(member) => Json(member).into_response(),
        Err(error) => route_error(error),
    }
}

pub(super) async fn remove(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<MemberBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    match service
        .dash_remove_organization_member(&claim.organization_id, &body.member_id)
        .await
    {
        Ok(_) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

pub(super) async fn update_role(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<RoleBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let organization_plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let role = body.role.trim().to_owned();
    if !valid_role(&role) || !organization_plugin.config.roles.contains_key(&role) {
        return invalid_role(organization_plugin);
    }
    match service
        .dash_update_organization_member_role(
            &claim.organization_id,
            &body.member_id,
            role,
        )
        .await
    {
        Ok(member) => Json(member).into_response(),
        Err(error) => route_error(error),
    }
}

fn preview(user: &crate::AuthUser) -> Value {
    json!({"id": user.id, "name": user.name, "email": user.email, "image": user.image})
}

pub(super) fn valid_role(role: &str) -> bool {
    let mut bytes = role.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && role.len() <= 64
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn invalid_role(plugin: &crate::OrganizationPlugin) -> Response {
    let allowed = plugin.config.roles.keys().cloned().collect::<Vec<_>>().join(", ");
    let message = format!("Invalid role. Allowed roles: {allowed}");
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"code": "BAD_REQUEST", "message": message})),
    )
        .into_response()
}
