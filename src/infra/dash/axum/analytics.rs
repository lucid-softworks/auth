use super::{auth, route, route_error};
use crate::{AuthService, AxumPluginRoute, DashPeriod, DashPlugin};
use axum::{
    Extension, Json,
    extract::Query,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

pub(super) fn routes(plugin: Arc<DashPlugin>) -> Vec<AxumPluginRoute> {
    vec![
        route(
            "/dash/user-stats",
            get(stats).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/user-graph-data",
            get(graph).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/user-retention-data",
            get(retention).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/ban-user",
            post(ban).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/ban-many-users",
            post(ban_many).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/unban-user",
            post(unban).layer(Extension(plugin)),
        ),
    ]
}

#[derive(Deserialize)]
struct PeriodQuery {
    period: Option<DashPeriod>,
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

async fn stats(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = auth::regular::<Value>(&plugin, &headers).await {
        return response;
    }
    match service.dash_user_stats().await {
        Ok(value) => Json(value).into_response(),
        Err(error) => route_error(error),
    }
}

async fn graph(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<PeriodQuery>,
) -> Response {
    if let Err(response) = auth::regular::<Value>(&plugin, &headers).await {
        return response;
    }
    match service
        .dash_user_graph(query.period.unwrap_or(DashPeriod::Daily))
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => route_error(error),
    }
}

async fn retention(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<PeriodQuery>,
) -> Response {
    if let Err(response) = auth::regular::<Value>(&plugin, &headers).await {
        return response;
    }
    match service
        .dash_user_retention(query.period.unwrap_or(DashPeriod::Weekly))
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => route_error(error),
    }
}

async fn ban(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<super::input::BanBody>,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let expires = match body.ban_expires {
        Some(value) => match chrono::DateTime::from_timestamp_millis(value) {
            Some(value) => Some(value),
            None => return crate::axum::api_error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
            ),
        },
        None => None,
    };
    match service
        .dash_ban_user(
            &claims.user_id,
            body.ban_reason,
            expires,
            body.delete_all_sessions,
        )
        .await
    {
        Ok(()) => Json(serde_json::json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}

async fn ban_many(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<super::input::BanBody>,
) -> Response {
    let claims = match auth::regular::<UsersClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let expires = body
        .ban_expires
        .and_then(chrono::DateTime::from_timestamp_millis);
    let mut banned = Vec::new();
    let mut skipped = Vec::new();
    for user_id in claims.user_ids {
        match service
            .dash_ban_user(
                &user_id,
                body.ban_reason.clone(),
                expires,
                body.delete_all_sessions,
            )
            .await
        {
            Ok(()) => banned.push(user_id),
            Err(_) => skipped.push(user_id),
        }
    }
    Json(serde_json::json!({
        "success": !banned.is_empty(),
        "bannedUserIds": banned,
        "skippedUserIds": skipped,
    }))
    .into_response()
}

async fn unban(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    match service.dash_unban_user(&claims.user_id).await {
        Ok(()) => Json(serde_json::json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}
