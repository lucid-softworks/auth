use super::{auth, input, route, route_error};
use crate::{AuthService, AxumPluginRoute, DashPlugin};
use axum::{
    Extension, Json,
    body::Body,
    extract::Query,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(super) fn routes(plugin: Arc<DashPlugin>) -> Vec<AxumPluginRoute> {
    vec![
        route(
            "/dash/list-users",
            get(list).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/export-users",
            get(export).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/create-user",
            post(create).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/delete-user",
            post(delete_one).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/delete-many-users",
            post(delete_many).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/user",
            get(details).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/user-organizations",
            get(organizations).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/update-user",
            post(update).layer(Extension(plugin.clone())),
        ),
        route(
            "/dash/unlink-account",
            post(unlink).layer(Extension(plugin)),
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
struct DetailsClaim {
    user_id: String,
    #[serde(default)]
    session_only: bool,
    #[serde(default)]
    account_only: bool,
}

#[derive(Deserialize)]
struct DetailQuery {
    #[serde(default, deserialize_with = "boolish")]
    minimal: bool,
}

fn boolish<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl serde::de::Visitor<'_> for Visitor {
        type Value = bool;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a boolean or boolean string")
        }
        fn visit_bool<E>(self, value: bool) -> Result<bool, E> {
            Ok(value)
        }
        fn visit_str<E>(self, value: &str) -> Result<bool, E> {
            Ok(value == "true")
        }
    }
    deserializer.deserialize_any(Visitor)
}

async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<input::UserListQuery>,
) -> Response {
    if let Err(response) = auth::regular::<Value>(&plugin, &headers).await {
        return response;
    }
    let query = match query.into_domain() {
        Ok(query) => query,
        Err(_) => return crate::axum::api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid query"),
    };
    match service.dash_list_users(&query).await {
        Ok((users, total)) => {
            let mut output = Vec::with_capacity(users.len());
            for user in users {
                match service.dash_user_json(&user).await {
                    Ok(user) => output.push(user),
                    Err(error) => return route_error(error),
                }
            }
            Json(json!({
                "users": output,
                "total": total,
                "offset": query.response_offset(),
                "limit": query.response_limit(),
                "onlineUsers": 0,
                "activityTrackingEnabled": plugin.options().activity_tracking.enabled,
            }))
            .into_response()
        }
        Err(error) => route_error(error),
    }
}

async fn export(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<input::UserListQuery>,
) -> Response {
    if let Err(response) = auth::regular::<Value>(&plugin, &headers).await {
        return response;
    }
    let query = match query.into_domain() {
        Ok(query) => query,
        Err(_) => return crate::axum::api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid query"),
    };
    let user_limit = query.limit.map(|limit| limit.max(0.0).floor() as usize);
    let mut page = 0_usize;
    let mut total = 0_usize;
    let mut bytes = Vec::new();
    loop {
        let remaining = user_limit.map(|limit| limit.saturating_sub(total));
        if remaining == Some(0) {
            break;
        }
        let mut batch_query = query.clone();
        batch_query.limit = Some(remaining.unwrap_or(10_000).min(10_000) as f64);
        batch_query.offset = Some(query.adapter_offset().saturating_add(page * 10_000) as f64);
        let users = match tokio::time::timeout(
            std::time::Duration::from_millis(300_000),
            service.dash_list_users(&batch_query),
        )
        .await
        {
            Ok(Ok((users, _))) => users,
            Ok(Err(error)) => return route_error(error),
            Err(_) => break,
        };
        if users.is_empty() {
            if page == 0 {
                return crate::axum::api_error(
                    StatusCode::FAILED_DEPENDENCY,
                    "FAILED_DEPENDENCY",
                    "Nothing found to export",
                );
            }
            break;
        }
        for user in users {
            let value = match service.dash_user_json(&user).await {
                Ok(value) => value,
                Err(error) => return route_error(error),
            };
            if serde_json::to_writer(&mut bytes, &value).is_err() {
                return route_error(crate::AuthError::Storage("failed to serialize export".into()));
            }
            bytes.push(b'\n');
            total += 1;
        }
        page += 1;
    }
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-ndjson"),
    );
    response
}

async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<Map<String, Value>>,
) -> Response {
    if let Err(response) = auth::regular::<Value>(&plugin, &headers).await {
        return response;
    }
    let send_verification = body
        .get("sendVerificationEmail")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match service.dash_create_user_body(body).await {
        Ok(user) => {
            if send_verification && !user.email_verified {
                let _ = service
                    .dash_send_verification_email(&user.id, "/")
                    .await;
            }
            match service.dash_user_json(&user).await {
                Ok(value) => Json(value).into_response(),
                Err(error) => route_error(error),
            }
        }
        Err(error) => route_error(error),
    }
}

async fn delete_one(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    match service.dash_delete_user(&claims.user_id).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => crate::axum::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Internal server error",
        ),
    }
}

async fn delete_many(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claims = match auth::regular::<UsersClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let mut deleted = Vec::new();
    let mut skipped = Vec::new();
    for user_id in claims.user_ids {
        match service.dash_delete_user(&user_id).await {
            Ok(()) => deleted.push(user_id),
            Err(_) => skipped.push(user_id),
        }
    }
    Json(json!({
        "success": !deleted.is_empty(),
        "skippedUserIds": skipped,
        "deletedUserIds": deleted,
    }))
    .into_response()
}

async fn details(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Query(query): Query<DetailQuery>,
) -> Response {
    let claims = match auth::regular::<DetailsClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    match service
        .dash_user_details(
            &claims.user_id,
            claims.session_only,
            claims.account_only,
            query.minimal,
        )
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => route_error(error),
    }
}

async fn organizations(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    match service.dash_user_organizations(&claims.user_id).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => route_error(error),
    }
}

async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<Map<String, Value>>,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    match service.dash_update_user_body(&claims.user_id, body).await {
        Ok(user) => Json(user).into_response(),
        Err(error) => route_error(error),
    }
}

async fn unlink(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Json(body): Json<input::UnlinkBody>,
) -> Response {
    let claims = match auth::regular::<UserClaim>(&plugin, &headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    match service
        .dash_unlink_account(&claims.user_id, &body.provider_id, &body.account_id)
        .await
    {
        Ok(()) => Json(json!({"success": true})).into_response(),
        Err(error) => route_error(error),
    }
}
