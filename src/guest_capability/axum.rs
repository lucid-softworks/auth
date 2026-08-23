use crate::{
    AuthError, AuthService, AxumPluginRoute, GuestGrant, NewGuestGrant,
    axum::http::{
        PeerAddress, auth_error, client_ip, current_session, user_agent, with_session_cookie,
    },
};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn routes(_service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/guest-grants",
            get(list_guest_grants).post(issue_guest_grant),
        ),
        AxumPluginRoute::new("/guest-grants/revoke", post(revoke_guest_grant)),
        AxumPluginRoute::new("/sign-in/guest-grant", post(redeem_guest_grant)),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueGuestGrantRequest {
    label: String,
    permissions: Vec<String>,
    #[serde(default)]
    resource_scopes: Vec<String>,
    valid_from: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    max_uses: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct RedeemGuestGrantRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeGuestGrantRequest {
    grant_id: String,
}

#[derive(Serialize)]
struct IssuedGuestGrantResponse {
    grant: GuestGrant,
    token: String,
}

#[derive(Serialize)]
struct GuestGrantsResponse {
    grants: Vec<GuestGrant>,
}

async fn issue_guest_grant(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<IssueGuestGrantRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let grant = NewGuestGrant {
        label: input.label,
        permissions: input.permissions,
        resource_scopes: input.resource_scopes,
        valid_from: input.valid_from.unwrap_or_else(Utc::now),
        expires_at: input.expires_at,
        max_uses: input.max_uses,
    };
    match service.issue_guest_grant(&actor, grant).await {
        Ok(issued) => Json(IssuedGuestGrantResponse {
            grant: issued.grant,
            token: issued.token,
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn list_guest_grants(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service.list_guest_grants(&actor).await {
        Ok(grants) => Json(GuestGrantsResponse { grants }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn revoke_guest_grant(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<RevokeGuestGrantRequest>,
) -> Response {
    let Some(actor) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let result = match Uuid::parse_str(&input.grant_id) {
        Ok(grant_id) => service.revoke_guest_grant(&actor, grant_id).await,
        Err(_) => Err(AuthError::InvalidRequest("invalid guest grant ID".into())),
    };
    match result {
        Ok(()) => Json(serde_json::json!({ "success": true })).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn redeem_guest_grant(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    Json(input): Json<RedeemGuestGrantRequest>,
) -> Response {
    match service
        .redeem_guest_grant(
            &input.token,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            let mut response =
                serde_json::to_value(crate::protocol::better_auth::SessionResponse::new(
                    &result.session,
                    result.token.clone(),
                ))
                .unwrap_or(Value::Null);
            if let Some(session) = response.get_mut("session").and_then(Value::as_object_mut) {
                session.insert(
                    "guestGrantId".into(),
                    Value::String(result.grant_id.to_string()),
                );
            }
            with_session_cookie(&service, &result.token, Some(true), Json(response))
        }
        Err(error) => auth_error(error),
    }
}
