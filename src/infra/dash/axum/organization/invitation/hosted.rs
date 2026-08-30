use super::super::{
    member::valid_role,
    support::{
        InvitationClaims, InviterClaims, OrganizationClaims, claims, error, plugin, route_error,
        synthetic_session,
    },
};
use crate::{
    AuthService, DashPlugin, NewOrganizationInvitation, OrganizationInvitationStatus,
};
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
pub(in crate::infra::dash::axum::organization) struct InviteBody {
    email: String,
    role: String,
    #[serde(rename = "invitedBy")]
    _invited_by: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::infra::dash::axum::organization) struct InvitationBody {
    invitation_id: String,
}

#[derive(Debug, Deserialize)]
pub(in crate::infra::dash::axum::organization) struct EmailBody {
    email: String,
}

pub(in crate::infra::dash::axum::organization) async fn list(
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
    let invitations = match plugin.store.list_invitations(&organization_id).await {
        Ok(invitations) => invitations,
        Err(error) => return route_error(error),
    };
    let mut output = Vec::with_capacity(invitations.len());
    for invitation in invitations {
        let user = service
            .dash_event_user_by_email(&invitation.email.to_lowercase())
            .await
            .ok()
            .flatten();
        let mut value = serde_json::to_value(invitation).expect("invitation serializes");
        value.as_object_mut().expect("invitation is an object").insert(
            "user".into(),
            user.map_or(Value::Null, |user| {
                json!({"id": user.id, "name": user.name, "email": user.email, "image": user.image})
            }),
        );
        output.push(value);
    }
    Json(output).into_response()
}

pub(in crate::infra::dash::axum::organization) async fn invite(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<InviteBody>,
) -> Response {
    let claim = match claims::<InviterClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let organization_plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let role = body.role.trim().to_owned();
    if !valid_role(&role) || !organization_plugin.config.roles.contains_key(&role) {
        return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid role");
    }
    if organization_plugin.config.invitation_email_sender.is_none() {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invitation email is not enabled",
        );
    }
    let inviter = match service.dash_event_user(&claim.invited_by).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invited by user not found"),
        Err(error) => return route_error(error),
    };
    let session = synthetic_session(inviter, None);
    match service
        .invite_organization_member(
            &session,
            NewOrganizationInvitation {
                email: body.email.to_lowercase(),
                role,
                organization_id: Some(claim.organization_id),
                team_ids: Vec::new(),
                resend: false,
            },
        )
        .await
    {
        Ok(invitation) => Json(invitation).into_response(),
        Err(error) => route_error(error),
    }
}

pub(in crate::infra::dash::axum::organization) async fn check_user_by_email(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<EmailBody>,
) -> Response {
    let claim = match claims::<OrganizationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let organization_plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let user = match service
        .dash_event_user_by_email(&body.email.to_lowercase())
        .await
    {
        Ok(user) => user,
        Err(error) => return route_error(error),
    };
    let Some(user) = user else {
        return Json(json!({"exists": false, "user": null, "isAlreadyMember": false}))
            .into_response();
    };
    let is_member = organization_plugin
        .store
        .find_member(&claim.organization_id, &user.id)
        .await
        .ok()
        .flatten()
        .is_some();
    Json(json!({
        "exists": true,
        "user": {"id": user.id, "name": user.name, "email": user.email, "image": user.image},
        "isAlreadyMember": is_member
    }))
    .into_response()
}

pub(in crate::infra::dash::axum::organization) async fn cancel(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<InvitationBody>,
) -> Response {
    let claim = match claims::<InvitationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    if claim.invitation_id != body.invitation_id {
        return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invitation ID mismatch");
    }
    let organization_plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let invitation = match organization_plugin
        .store
        .find_invitation(&body.invitation_id)
        .await
    {
        Ok(Some(invitation)) if invitation.organization_id == claim.organization_id => invitation,
        Ok(_) => return error(StatusCode::NOT_FOUND, "NOT_FOUND", "Invitation not found"),
        Err(error) => return route_error(error),
    };
    match service.dash_event_user(&invitation.inviter_id).await {
        Ok(Some(_)) => {}
        _ => return error(StatusCode::NOT_FOUND, "NOT_FOUND", "Inviter not found or is not associated with this invitation"),
    }
    match service
        .dash_cancel_organization_invitation(invitation)
        .await
    {
        Ok(_) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

pub(in crate::infra::dash::axum::organization) async fn resend(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<InvitationBody>,
) -> Response {
    let claim = match claims::<InvitationClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    if claim.invitation_id != body.invitation_id {
        return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invitation ID mismatch");
    }
    let organization_plugin = match plugin(&service) {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let invitation = match organization_plugin
        .store
        .find_invitation(&body.invitation_id)
        .await
    {
        Ok(Some(invitation)) if invitation.organization_id == claim.organization_id => invitation,
        Ok(_) => return error(StatusCode::NOT_FOUND, "NOT_FOUND", "Invitation not found"),
        Err(error) => return route_error(error),
    };
    if invitation.status != OrganizationInvitationStatus::Pending {
        return error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Only pending invitations can be resent",
        );
    }
    let inviter = match service.dash_event_user(&invitation.inviter_id).await {
        Ok(Some(user)) => user,
        _ => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Inviter not found or is not associated with this invitation"),
    };
    let session = synthetic_session(inviter, None);
    match service
        .invite_organization_member(
            &session,
            NewOrganizationInvitation {
                email: invitation.email,
                role: invitation.role,
                organization_id: Some(claim.organization_id),
                team_ids: Vec::new(),
                resend: true,
            },
        )
        .await
    {
        Ok(_) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

pub(in crate::infra::dash::axum::organization) async fn check_user_exists(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<EmailBody>,
) -> Response {
    if let Err(response) = claims::<Value>(&dash, &headers).await {
        return response;
    }
    if !body.email.contains('@') {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid email",
        );
    }
    match service
        .dash_event_user_by_email(&body.email.to_lowercase())
        .await
    {
        Ok(user) => Json(json!({
            "exists": user.is_some(), "userId": user.as_ref().map(|user| &user.id)
        }))
        .into_response(),
        Err(error) => route_error(error),
    }
}
