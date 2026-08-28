use super::{auth, input, route, route_error};
use crate::{AuthService, AxumPluginRoute, DashPlugin};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub(super) fn routes(plugin: Arc<DashPlugin>) -> Vec<AxumPluginRoute> {
    vec![
        route(
            "/dash/set-password",
            post(set_password).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/sessions/revoke",
            post(revoke).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/sessions/revoke-all",
            post(revoke_all).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/sessions/revoke-many",
            post(revoke_many).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/impersonate-user",
            get(impersonate).layer(Extension(plugin)),
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionClaim {
    session_id: String,
    user_id: String,
}

#[derive(Deserialize)]
struct ImpersonationQuery {
    impersonation_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonationClaim {
    user_id: String,
    redirect_url: String,
    impersonated_by: Option<String>,
}

async fn set_password(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<input::PasswordBody>,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if body.password.encode_utf16().count() < 8 {
        return crate::axum::api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Too small: expected string to have >=8 characters",
        );
    }
    match service
        .dash_set_password(&claims.user_id, body.password)
        .await
    {
        Ok(()) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

async fn revoke(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claims = match auth::regular::<SessionClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    match service
        .dash_revoke_owned_session(&claims.user_id, &claims.session_id)
        .await
    {
        Ok(()) => Json(json!({"success": true})).into_response(),
        Err(crate::AuthError::NotFound) => crate::axum::api_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Session not found",
        ),
        Err(error) => route_error(error),
    }
}

async fn revoke_all(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<input::UserIdBody>,
) -> Response {
    if let Err(response) = auth::regular::<serde_json::Value>(&plugin, &headers).await {
        return response;
    }
    if let Err(error) = service.dash_find_user(&body.user_id).await {
        return route_error(error);
    }
    match service.dash_revoke_all_sessions(&body.user_id).await {
        Ok(()) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

async fn revoke_many(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claims = match auth::regular::<UsersClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let count = claims.user_ids.len();
    for user_id in claims.user_ids {
        if let Err(error) = service.dash_revoke_all_sessions(&user_id).await {
            return route_error(error);
        }
    }
    Json(json!({"success": true, "revokedCount": count})).into_response()
}

async fn impersonate(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<ImpersonationQuery>,
) -> Response {
    let claims = match auth::token::<ImpersonationClaim>(&plugin, &query.impersonation_token).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if crate::axum::validate_trusted_origin_value(&service, &headers, &claims.redirect_url).is_err()
    {
        return crate::axum::api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid redirect URL",
        );
    }
    match service
        .dash_impersonate_user(&claims.user_id, claims.impersonated_by)
        .await
    {
        Ok(result) => {
            let mut response = Response::new(axum::body::Body::empty());
            *response.status_mut() = StatusCode::FOUND;
            let Ok(location) = HeaderValue::from_str(&claims.redirect_url) else {
                return crate::axum::api_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid redirect URL",
                );
            };
            response.headers_mut().insert(header::LOCATION, location);
            crate::axum::http::with_bound_session_cookie(
                &service,
                &headers,
                &result.session.user.id,
                &result.token,
                Some(true),
                response,
            )
            .await
        }
        Err(error) => route_error(error),
    }
}
