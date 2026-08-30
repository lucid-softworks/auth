#![cfg(all(feature = "axum", feature = "sqlite"))]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, AuthStore, DatabaseScimStore, SCIM_GROUP_SCHEMA, SCIM_MEDIA_TYPE,
    SCIM_USER_SCHEMA, ScimBearerCredential, ScimConnection, ScimOptions, ScimPlugin, ScimStore,
    sqlite::{SqliteAdapterConfig, SqliteStore},
};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

const TOKEN: &str = "database-scim-token";

async fn application() -> (Router, Arc<DatabaseScimStore>, Arc<SqliteStore>) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth_store = Arc::new(SqliteStore::new(pool, SqliteAdapterConfig::default()));
    let scim_store = Arc::new(DatabaseScimStore::new(auth_store.clone()));
    let options = ScimOptions {
        connections: vec![ScimConnection::new(
            "directory-1",
            vec![ScimBearerCredential::new("credential-1", TOKEN)],
        )],
        ..ScimOptions::default()
    };
    let plugin = ScimPlugin::new(options, scim_store.clone()).unwrap();
    let mut config = AuthConfig::new([232_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config.add_plugin(plugin).unwrap();
    let service = Arc::new(AuthService::new(auth_store.clone(), config));
    auth_store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    (lucid_auth::axum::router(service), scim_store, auth_store)
}

fn request(method: &str, path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(format!("/api/auth{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
}

async fn send_json(app: Router, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            request(method, path)
                .header(header::CONTENT_TYPE, SCIM_MEDIA_TYPE)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

#[tokio::test]
async fn core_resources_round_trip_through_native_sqlite_transactions() {
    let (app, store, auth_store) = application().await;
    let (status, user) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Users",
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "externalId": "employee-1",
            "userName": "luna@example.com",
            "name": {"givenName": "Luna", "familyName": "Lake"},
            "emails": [{"value": "luna@example.com", "type": "work", "primary": true}],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{user:#}");
    let user_id = user["id"].as_str().unwrap();
    let persisted_user = store
        .find_user("directory-1", user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted_user.resource.user_name, "luna@example.com");
    let auth_user_id = persisted_user.user_id.clone();

    let (status, duplicate) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Users",
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "userName": "LUNA@example.com",
            "name": {"formatted": "Other User"},
            "emails": [{"value": "other@example.com", "type": "work", "primary": true}],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{duplicate:#}");
    assert!(
        auth_store
            .find_user_by_email("other@example.com")
            .await
            .unwrap()
            .is_none(),
        "the Better Auth user must roll back with the duplicate SCIM row"
    );

    let (status, updated_user) = send_json(
        app.clone(),
        "PUT",
        &format!("/scim/v2/Users/{user_id}"),
        json!({
            "schemas": [SCIM_USER_SCHEMA],
            "externalId": "employee-1",
            "userName": "luna.lake@example.com",
            "name": {"formatted": "Luna Rivers"},
            "emails": [{"value": "luna.rivers@example.com", "type": "work", "primary": true}],
            "active": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated_user:#}");
    let auth_user = auth_store
        .find_user_by_id(&auth_user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth_user.name, "Luna Rivers");
    assert_eq!(auth_user.email, "luna.rivers@example.com");
    assert!(!auth_user.email_verified);

    let (status, group) = send_json(
        app.clone(),
        "POST",
        "/scim/v2/Groups",
        json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "externalId": "team-1",
            "displayName": "Engineering",
            "members": [{"value": user_id}]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group:#}");
    let group_id = group["id"].as_str().unwrap();
    let persisted_group = store
        .find_group("directory-1", group_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted_group.resource.members.len(), 1);
    assert_eq!(persisted_group.resource.members[0].value, user_id);

    let (status, updated) = send_json(
        app.clone(),
        "PUT",
        &format!("/scim/v2/Groups/{group_id}"),
        json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": "Platform",
            "members": []
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated:#}");
    assert_eq!(updated["displayName"], "Platform");

    let response = app
        .clone()
        .oneshot(
            request("DELETE", &format!("/scim/v2/Users/{user_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        store
            .find_user("directory-1", user_id)
            .await
            .unwrap()
            .is_none()
    );
}
