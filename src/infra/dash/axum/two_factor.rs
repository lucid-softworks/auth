use super::{DashPlugin, route};
use crate::{AuthService, AxumPluginRoute};
use axum::{Extension, Json, http::{HeaderMap, StatusCode}, response::{IntoResponse, Response}, routing::post};
use serde_json::json;
use std::sync::Arc;

use super::organization::support::{UserClaims, claims, error, route_error};

pub(super) fn routes(plugin: Arc<DashPlugin>) -> Vec<AxumPluginRoute> {
    vec![
        route("/dash/enable-two-factor", post(enable).layer(Extension(plugin.clone()))),
        route("/dash/complete-two-factor-setup", post(complete).layer(Extension(plugin.clone()))),
        route("/dash/view-two-factor-totp-uri", post(view_totp_uri).layer(Extension(plugin.clone()))),
        route("/dash/view-backup-codes", post(view_backup_codes).layer(Extension(plugin.clone()))),
        route("/dash/disable-two-factor", post(disable).layer(Extension(plugin.clone()))),
        route("/dash/generate-backup-codes", post(generate_backup_codes).layer(Extension(plugin))),
    ]
}

async fn enable(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claim = match claims::<UserClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match service.two_factor_plugin() {
        Ok(plugin) => plugin,
        Err(_) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Two-factor authentication plugin is not enabled"),
    };
    if plugin.config.totp.disabled {
        return error(StatusCode::BAD_REQUEST, "TOTP_NOT_CONFIGURED", "TOTP is not configured");
    }
    let user = match service.dash_event_user(&claim.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found"),
        Err(error_value) => return route_error(error_value),
    };
    match plugin.store.two_factor_enabled(&claim.user_id).await {
        Ok(true) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Two-factor authentication is already enabled for this user"),
        Ok(false) => {}
        Err(error_value) => return route_error(error_value),
    }
    match service.dash_enable_two_factor(&claim.user_id, &user.email).await {
        Ok(setup) => Json(json!({
            "success": true,
            "totpURI": setup.totp_uri,
            "secret": setup.secret,
            "backupCodes": setup.backup_codes,
        })).into_response(),
        Err(error_value) => route_error(error_value),
    }
}

async fn complete(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claim = match claims::<UserClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match service.two_factor_plugin() {
        Ok(plugin) => plugin,
        Err(_) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Two-factor authentication plugin is not enabled"),
    };
    match service.dash_event_user(&claim.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found"),
        Err(error_value) => return route_error(error_value),
    }
    match plugin.store.two_factor_enabled(&claim.user_id).await {
        Ok(true) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Two-factor authentication is already enabled for this user"),
        Ok(false) => {}
        Err(error_value) => return route_error(error_value),
    }
    match plugin.store.complete_two_factor_enrollment(&claim.user_id).await {
        Ok(true) => Json(json!({"success": true})).into_response(),
        Ok(false) => error(StatusCode::BAD_REQUEST, "TWO_FACTOR_SETUP_NOT_PENDING", "Two-factor authentication setup has not been started"),
        Err(error_value) => route_error(error_value),
    }
}

async fn view_totp_uri(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claim = match claims::<UserClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match service.two_factor_plugin() {
        Ok(plugin) => plugin,
        Err(_) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Two-factor authentication plugin is not enabled"),
    };
    if plugin.config.totp.disabled {
        return error(StatusCode::BAD_REQUEST, "TOTP_NOT_CONFIGURED", "TOTP is not configured");
    }
    let account = match service.dash_event_user(&claim.user_id).await {
        Ok(Some(user)) => user.email,
        Ok(None) => claim.user_id.clone(),
        Err(error_value) => return route_error(error_value),
    };
    match service.dash_two_factor_totp_uri(&claim.user_id, &account).await {
        Ok(Some(totp_uri)) => Json(json!({"totpURI": totp_uri})).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "NOT_FOUND", "Two-factor authentication not set up for this user"),
        Err(error_value) => route_error(error_value),
    }
}

async fn view_backup_codes(
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = claims::<UserClaims>(&dash, &headers).await {
        return response;
    }
    error(StatusCode::FORBIDDEN, "FORBIDDEN", "Backup codes cannot be viewed after initial setup. Generate new codes instead.")
}

async fn disable(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claim = match claims::<UserClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    let plugin = match service.two_factor_plugin() {
        Ok(plugin) => plugin,
        Err(_) => return error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Two-factor authentication is not enabled"),
    };
    if let Err(error_value) = plugin.store.delete_two_factor(&claim.user_id).await {
        return route_error(error_value);
    }
    match plugin.store.set_two_factor_enabled(&claim.user_id, false).await {
        Ok(()) => Json(json!({"success": true})).into_response(),
        Err(error_value) => route_error(error_value),
    }
}

async fn generate_backup_codes(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claim = match claims::<UserClaims>(&dash, &headers).await {
        Ok(claim) => claim,
        Err(response) => return response,
    };
    if service.two_factor_plugin().is_err() {
        return error(StatusCode::NOT_FOUND, "NOT_FOUND", "Two-factor authentication not set up for this user");
    }
    match service.dash_generate_backup_codes(&claim.user_id).await {
        Ok(Some(codes)) => Json(json!({"backupCodes": codes})).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "NOT_FOUND", "Two-factor authentication not set up for this user"),
        Err(error_value) => route_error(error_value),
    }
}
