use super::{auth, input, route, route_error};
use crate::{AuthService, AxumPluginRoute, DashPlugin};
use axum::{
    Extension, Json,
    body::{Body, Bytes},
    extract::Query,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio_stream::wrappers::ReceiverStream;

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
        route("/dash/user", get(details).layer(Extension(plugin.clone()))),
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
        Err(_) => {
            return crate::axum::api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid query");
        }
    };
    match service.dash_list_users(&query).await {
        Ok((users, total)) => {
            let online_users = service.dash_online_users().await.unwrap_or(0);
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
                "onlineUsers": online_users,
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
        Err(_) => {
            return crate::axum::api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid query");
        }
    };
    let user_limit = query.limit.map(|limit| limit.max(0.0).floor() as usize);
    let first_limit = user_limit.unwrap_or(10_000).min(10_000);
    if first_limit == 0 {
        return crate::axum::api_error(
            StatusCode::FAILED_DEPENDENCY,
            "FAILED_DEPENDENCY",
            "Nothing found to export",
        );
    }
    let first = match service
        .dash_export_users(&query, first_limit, query.adapter_offset())
        .await
    {
        Ok(users) if !users.is_empty() => users,
        Ok(_) => {
            return crate::axum::api_error(
                StatusCode::FAILED_DEPENDENCY,
                "FAILED_DEPENDENCY",
                "Nothing found to export",
            );
        }
        Err(error) => return route_error(error),
    };
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(1);
    tokio::spawn(stream_export(service, query, user_limit, first, sender));
    let mut response = Response::new(Body::from_stream(ReceiverStream::new(receiver)));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-ndjson"),
    );
    response
}

async fn stream_export(
    service: Arc<AuthService>,
    query: crate::DashUserListQuery,
    user_limit: Option<usize>,
    first: Vec<crate::AuthUser>,
    sender: tokio::sync::mpsc::Sender<Result<Bytes, Infallible>>,
) {
    let mut users = first;
    let mut exported = 0_usize;
    loop {
        let batch_len = users.len();
        let Some(bytes) = serialize_export_batch(&service, users).await else {
            return;
        };
        exported += batch_len;
        if !matches!(
            tokio::time::timeout(Duration::from_millis(300_000), sender.send(Ok(bytes))).await,
            Ok(Ok(()))
        ) {
            return;
        }
        let remaining = user_limit.map(|limit| limit.saturating_sub(exported));
        if remaining == Some(0) || (batch_len < 10_000 && user_limit.is_none()) {
            return;
        }
        let limit = remaining.unwrap_or(10_000).min(10_000);
        match service
            .dash_export_users(
                &query,
                limit,
                query.adapter_offset().saturating_add(exported),
            )
            .await
        {
            Ok(next) if !next.is_empty() => users = next,
            _ => return,
        }
    }
}

async fn serialize_export_batch(
    service: &AuthService,
    users: Vec<crate::AuthUser>,
) -> Option<Bytes> {
    let mut bytes = Vec::new();
    for user in users {
        let value = service.dash_user_json(&user).await.ok()?;
        serde_json::to_writer(&mut bytes, &value).ok()?;
        bytes.push(b'\n');
    }
    Some(Bytes::from(bytes))
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
            if send_verification
                && !user.email_verified
                && let Err(error) = service
                    .dash_send_create_verification_email(user.clone())
                    .await
            {
                return route_error(error);
            }
            match service.dash_plain_user_json(&user).await {
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
        Ok(user) => match service.dash_plain_user_json(&user).await {
            Ok(user) => Json(user).into_response(),
            Err(error) => route_error(error),
        },
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
