use super::{auth, input, route, route_error};
use crate::{AuthService, AxumPluginRoute, DashPlugin};
use axum::{
    Extension, Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub(super) fn routes(plugin: Arc<DashPlugin>) -> Vec<AxumPluginRoute> {
    vec![
        route(
            "/dash/send-verification-email",
            post(send_verification).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/send-many-verification-emails",
            post(send_many_verifications).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/send-reset-password-email",
            post(send_reset).layer(Extension(plugin)),
        ),
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserClaim {
    user_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsersClaim {
    user_ids: Vec<String>,
}

fn validate_callback(
    service: &AuthService,
    headers: &HeaderMap,
    callback_url: &str,
) -> Result<(), Response> {
    crate::axum::validate_trusted_origin_value(service, headers, callback_url).map_err(|_| {
        crate::axum::api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid callback URL",
        )
    })
}

async fn send_verification(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<input::CallbackBody>,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if let Err(response) = validate_callback(&service, &headers, &body.callback_url) {
        return response;
    }
    match service
        .dash_send_verification_email(&claims.user_id, &body.callback_url)
        .await
    {
        Ok(()) => Json(json!({"success": true})).into_response(),
        Err(crate::AuthError::EmailAlreadyVerified) => crate::axum::api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Email is already verified",
        ),
        Err(crate::AuthError::VerificationEmailNotEnabled) => crate::axum::api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Email verification is not enabled",
        ),
        Err(error) => route_error(error),
    }
}

async fn send_many_verifications(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<input::CallbackBody>,
) -> Response {
    let claims = match auth::regular::<UsersClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if let Err(response) = validate_callback(&service, &headers, &body.callback_url) {
        return response;
    }
    if !service.dash_verification_email_enabled() {
        return crate::axum::api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Email verification is not enabled",
        );
    }
    let mut sent = Vec::new();
    let mut skipped = Vec::new();
    for user_id in claims.user_ids {
        match service
            .dash_send_verification_email(&user_id, &body.callback_url)
            .await
        {
            Ok(()) => sent.push(user_id),
            Err(_) => skipped.push(user_id),
        }
    }
    Json(json!({
        "success": !sent.is_empty(),
        "sentEmailUserIds": sent,
        "skippedEmailUserIds": skipped,
    }))
    .into_response()
}

async fn send_reset(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<input::CallbackBody>,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if let Err(response) = validate_callback(&service, &headers, &body.callback_url) {
        return response;
    }
    match service
        .dash_send_reset_password_email(&claims.user_id, &body.callback_url)
        .await
    {
        Ok(()) => Json(json!({
            "status": true,
            "message": "Password reset email sent",
        }))
        .into_response(),
        Err(error) => route_error(error),
    }
}
