use super::support::{error, route_error};
use crate::{AuthService, DashApiClient, DashPlugin, DashRequest};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

mod hosted;

pub(super) use hosted::{
    cancel, check_user_by_email, check_user_exists, invite, list, resend,
};

#[derive(Debug, Deserialize)]
pub(super) struct TokenQuery {
    token: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct HandoffQuery {
    handoff: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct CompleteBody {
    token: String,
    password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteInvitation {
    email: String,
    name: Option<String>,
    status: String,
    expires_at: Option<DateTime<Utc>>,
    redirect_url: Option<String>,
    auth_mode: Option<String>,
}

pub(super) async fn accept(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    let invitation = match verify(&dash, &query.token).await {
        Ok(invitation) => invitation,
        Err(response) => return response,
    };
    if let Ok(Some(user)) = service.dash_event_user_by_email(&invitation.email.to_lowercase()).await {
        mark_accepted(&dash, &query.token, &user.id).await;
        return redirect_with_optional_session(&service, &headers, user, &invitation).await;
    }
    if uses_platform(invitation.auth_mode.as_deref()) {
        let mut target = match url::Url::parse(&dash.resolved_connection().api_url)
            .and_then(|base| base.join("/invite/accept"))
        {
            Ok(target) => target,
            Err(_) => return invitation_error("Invalid or expired invitation."),
        };
        target.query_pairs_mut().append_pair("token", &query.token).append_pair(
            "callback",
            &format!(
                "{}{}{}",
                service.dash_auth_base_url().trim_end_matches('/'),
                service.base_path(),
                "/dash/complete-invitation"
            ),
        );
        return redirect(target.as_str());
    }
    let user = match create_invited_user(&service, &invitation, None).await {
        Ok(user) => user,
        Err(error) => return route_error(error),
    };
    mark_accepted(&dash, &query.token, &user.id).await;
    redirect_with_optional_session(&service, &headers, user, &invitation).await
}

pub(super) async fn complete(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<CompleteBody>,
) -> Response {
    let invitation = match verify(&dash, &body.token).await {
        Ok(invitation) => invitation,
        Err(response) => return response,
    };
    complete_response(&service, &dash, &headers, invitation, body.token, body.password, false).await
}

pub(super) async fn handoff(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<HandoffQuery>,
) -> Response {
    if query.handoff.is_empty() {
        return invitation_error("This invitation link has expired. Please try again.");
    }
    let api = DashApiClient::new(dash.resolved_connection());
    let response = api
        .execute(DashRequest::post(
            "/api/internal/invitations/redeem-handoff",
            json!({"handoff": query.handoff}),
        ))
        .await;
    let Some(data) = response.ok().and_then(|response| response.data) else {
        return invitation_error("This invitation link has expired. Please try again.");
    };
    let Some(token) = data.get("invitationToken").and_then(Value::as_str).map(str::to_owned) else {
        return invitation_error("This invitation link has expired. Please try again.");
    };
    let password = data.get("password").and_then(Value::as_str).map(str::to_owned);
    let invitation = match verify(&dash, &token).await {
        Ok(invitation) => invitation,
        Err(response) => return response,
    };
    complete_response(&service, &dash, &headers, invitation, token, password, true).await
}

pub(super) async fn social(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Authentication required.");
    };
    let invitation = match verify(&dash, &query.token).await {
        Ok(invitation) => invitation,
        Err(response) => return response,
    };
    if !uses_platform(invitation.auth_mode.as_deref()) {
        return invitation_error("This invitation cannot be completed through this endpoint.");
    }
    if !session.user.email.eq_ignore_ascii_case(&invitation.email) {
        return invitation_error("Signed-in account does not match this invitation.");
    }
    mark_accepted(&dash, &query.token, &session.user.id).await;
    let response = redirect(&trusted_redirect(&service, invitation.redirect_url.as_deref()));
    if creates_session(invitation.auth_mode.as_deref()) {
        response
    } else {
        if let Err(error) = service
            .revoke_current_user_session_token(&session, &session.session.token)
            .await
        {
            return route_error(error);
        }
        crate::axum::http::clear_session_cookie_from_request(&service, &headers, response)
    }
}

async fn complete_response(
    service: &AuthService,
    dash: &DashPlugin,
    headers: &HeaderMap,
    invitation: RemoteInvitation,
    token: String,
    password: Option<String>,
    as_redirect: bool,
) -> Response {
    if !uses_platform(invitation.auth_mode.as_deref()) {
        return invitation_error("This invitation cannot be completed through this endpoint.");
    }
    let existing = service
        .dash_event_user_by_email(&invitation.email.to_lowercase())
        .await
        .ok()
        .flatten();
    if existing.is_none() && password.is_none() && invitation.auth_mode.as_deref() != Some("create_with_session") {
        return invitation_error("Password is required to complete this invitation.");
    }
    let user = match existing {
        Some(user) => user,
        None => match create_invited_user(service, &invitation, password).await {
            Ok(user) => user,
            Err(error) => return route_error(error),
        },
    };
    mark_accepted(dash, &token, &user.id).await;
    let target = trusted_redirect(service, invitation.redirect_url.as_deref());
    let body = if as_redirect {
        redirect(&target)
    } else {
        Json(json!({"success": true, "redirectUrl": target})).into_response()
    };
    if creates_session(invitation.auth_mode.as_deref()) {
        match service.dash_invitation_session(user.clone()).await {
            Ok(result) => crate::axum::http::with_bound_session_cookie(
                service,
                headers,
                &user.id,
                &result.token,
                Some(true),
                body,
            )
            .await,
            Err(error) => route_error(error),
        }
    } else {
        body
    }
}

async fn create_invited_user(
    service: &AuthService,
    invitation: &RemoteInvitation,
    password: Option<String>,
) -> Result<crate::AuthUser, crate::AuthError> {
    let name = invitation
        .name
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| invitation.email.split('@').next().unwrap_or_default().to_owned());
    service
        .dash_invitation_user(invitation.email.to_lowercase(), name, password)
        .await
}

async fn redirect_with_optional_session(
    service: &AuthService,
    headers: &HeaderMap,
    user: crate::AuthUser,
    invitation: &RemoteInvitation,
) -> Response {
    let response = redirect(&trusted_redirect(service, invitation.redirect_url.as_deref()));
    if !creates_session(invitation.auth_mode.as_deref()) {
        return response;
    }
    match service.dash_invitation_session(user.clone()).await {
        Ok(result) => crate::axum::http::with_bound_session_cookie(
            service,
            headers,
            &user.id,
            &result.token,
            Some(true),
            response,
        )
        .await,
        Err(error) => route_error(error),
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
async fn verify(dash: &DashPlugin, token: &str) -> Result<RemoteInvitation, Response> {
    let api = DashApiClient::new(dash.resolved_connection());
    let response = api
        .execute(DashRequest::post(
            "/api/internal/invitations/verify",
            json!({"token": token}),
        ))
        .await
        .ok();
    let Some(data) = response.and_then(|response| response.data) else {
        return Err(invitation_error("Invalid or expired invitation."));
    };
    let invitation: RemoteInvitation = serde_json::from_value(data)
        .map_err(|_| invitation_error("Invalid or expired invitation."))?;
    if invitation.status != "pending" {
        return Err(invitation_error(&format!(
            "This invitation has already been {}.",
            invitation.status
        )));
    }
    if invitation.expires_at.is_some_and(|expires| expires < Utc::now()) {
        let _ = api
            .execute(DashRequest::post(
                "/api/internal/invitations/mark-expired",
                json!({"token": token}),
            ))
            .await;
        return Err(invitation_error("This invitation has expired."));
    }
    Ok(invitation)
}

async fn mark_accepted(dash: &DashPlugin, token: &str, user_id: &str) {
    let _ = DashApiClient::new(dash.resolved_connection())
        .execute(DashRequest::post(
            "/api/internal/invitations/mark-accepted",
            json!({"token": token, "userId": user_id}),
        ))
        .await;
}

fn uses_platform(mode: Option<&str>) -> bool {
    matches!(mode, Some("auth" | "credential_setup" | "create_with_session" | "create_no_session"))
}

fn creates_session(mode: Option<&str>) -> bool {
    mode != Some("create_no_session")
}

fn trusted_redirect(service: &AuthService, raw: Option<&str>) -> String {
    let fallback = service.dash_auth_base_url();
    let Some(raw) = raw else {
        return fallback;
    };
    let raw = raw.trim();
    if raw.is_empty()
        || raw.starts_with("//")
        || raw.contains('\\')
        || raw.chars().any(|character| character.is_control())
    {
        return fallback;
    }
    let parsed = url::Url::parse(raw).or_else(|_| {
        url::Url::parse(&fallback).and_then(|base| base.join(raw))
    });
    let Ok(parsed) = parsed else {
        return fallback;
    };
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !service.trusts_origin(&parsed.origin().ascii_serialization())
    {
        return fallback;
    }
    parsed.into()
}

fn redirect(target: &str) -> Response {
    match header::HeaderValue::from_str(target) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => invitation_error("Invalid or expired invitation."),
    }
}

fn invitation_error(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"code": "BAD_REQUEST", "message": message})),
    )
        .into_response()
}
