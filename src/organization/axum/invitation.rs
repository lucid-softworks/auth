use super::organization::{id, optional_id};
use crate::{
    AuthError, AuthService, AxumPluginRoute, NewOrganizationInvitation,
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

pub(super) fn routes() -> Vec<AxumPluginRoute> {
    vec![
        route_post("/organization/invite-member", invite),
        route_post("/organization/cancel-invitation", cancel),
        route_post("/organization/accept-invitation", accept),
        route_get("/organization/get-invitation", get_invitation),
        route_post("/organization/reject-invitation", reject),
        route_get("/organization/list-invitations", list),
        route_get("/organization/list-user-invitations", list_user_invitations),
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
struct InviteRequest {
    email: String,
    role: RoleInput,
    organization_id: Option<String>,
    team_id: Option<TeamInput>,
    resend: Option<bool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RoleInput {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TeamInput {
    One(String),
    Many(Vec<String>),
}

async fn invite(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<InviteRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match optional_id(input.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    let role = match input.role {
        RoleInput::One(role) => role,
        RoleInput::Many(roles) => roles.join(","),
    };
    let raw_team_ids = match input.team_id {
        Some(TeamInput::One(id)) => vec![id],
        Some(TeamInput::Many(ids)) => ids,
        None => Vec::new(),
    };
    if raw_team_ids.iter().any(|team_id| team_id.contains(',')) {
        return auth_error(
            crate::OrganizationError::bad_request(
                "INVALID_TEAM_ID",
                "Team id contains a reserved character",
            )
            .into(),
        );
    }
    let mut team_ids = Vec::with_capacity(raw_team_ids.len());
    for team_id in raw_team_ids {
        match id(&team_id) {
            Ok(team_id) => team_ids.push(team_id),
            Err(error) => return auth_error(error),
        }
    }
    match service
        .invite_organization_member(
            &session,
            NewOrganizationInvitation {
                email: input.email,
                role,
                organization_id,
                team_ids,
                resend: input.resend.unwrap_or(false),
            },
        )
        .await
    {
        Ok(invitation) => Json(invitation).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InvitationRequest {
    invitation_id: String,
}

async fn accept(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<InvitationRequest>,
) -> Response {
    with_invitation(&service, &headers, &input.invitation_id, Action::Accept).await
}

async fn cancel(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<InvitationRequest>,
) -> Response {
    with_invitation(&service, &headers, &input.invitation_id, Action::Cancel).await
}

async fn reject(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<InvitationRequest>,
) -> Response {
    with_invitation(&service, &headers, &input.invitation_id, Action::Reject).await
}

enum Action {
    Accept,
    Cancel,
    Reject,
}

async fn with_invitation(
    service: &AuthService,
    headers: &HeaderMap,
    invitation_id: &str,
    action: Action,
) -> Response {
    let Some(session) = current_session(service, headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let invitation_id = match id(invitation_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match action {
        Action::Accept => match service
            .accept_organization_invitation(&session, invitation_id)
            .await
        {
            Ok(result) => Json(result).into_response(),
            Err(error) => auth_error(error),
        },
        Action::Cancel => match service
            .cancel_organization_invitation(&session, invitation_id)
            .await
        {
            Ok(invitation) => Json(invitation).into_response(),
            Err(error) => auth_error(error),
        },
        Action::Reject => match service
            .reject_organization_invitation(&session, invitation_id)
            .await
        {
            Ok(invitation) => Json(RejectResponse {
                invitation,
                member: None,
            })
            .into_response(),
            Err(error) => auth_error(error),
        },
    }
}

#[derive(Serialize)]
struct RejectResponse {
    invitation: crate::OrganizationInvitation,
    member: Option<crate::OrganizationMember>,
}

#[derive(Deserialize)]
struct InvitationQuery {
    id: String,
}

async fn get_invitation(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<InvitationQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let invitation_id = match id(&query.id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .get_organization_invitation(&session, invitation_id)
        .await
    {
        Ok(invitation) => Json(invitation).into_response(),
        Err(error) => auth_error(error),
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
    organization_id: Option<String>,
    email: Option<String>,
}

async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let organization_id = match optional_id(query.organization_id) {
        Ok(id) => id,
        Err(error) => return auth_error(error),
    };
    match service
        .list_organization_invitations(&session, organization_id)
        .await
    {
        Ok(invitations) => Json(invitations).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn list_user_invitations(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    if query.email.is_some() {
        return auth_error(AuthError::InvalidRequest(
            "User email cannot be passed for client side API calls".into(),
        ));
    }
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service
        .list_current_user_organization_invitations(&session)
        .await
    {
        Ok(invitations) => {
            let plugin = match service.organization_plugin() {
                Ok(plugin) => plugin,
                Err(error) => return auth_error(error),
            };
            let mut output = Vec::with_capacity(invitations.len());
            for invitation in invitations {
                let organization = match plugin
                    .store
                    .find_organization_by_id(invitation.organization_id)
                    .await
                {
                    Ok(Some(organization)) => organization,
                    Ok(None) => continue,
                    Err(error) => return auth_error(error),
                };
                output.push(UserInvitationResponse {
                    invitation,
                    organization_name: organization.name,
                });
            }
            Json(output).into_response()
        }
        Err(error) => auth_error(error),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserInvitationResponse {
    #[serde(flatten)]
    invitation: crate::OrganizationInvitation,
    organization_name: String,
}
