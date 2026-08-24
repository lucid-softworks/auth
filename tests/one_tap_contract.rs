use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{AuthConfig, AuthService, MemoryStore, OneTapConfig, OneTapPlugin};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

fn application(client_id: Option<&str>) -> (Router, Arc<AuthService>) {
    let mut config = AuthConfig::new([113_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    let one_tap = client_id.map_or_else(OneTapConfig::default, |client_id| {
        OneTapConfig::default().with_client_id(client_id)
    });
    config.add_plugin(OneTapPlugin::new(one_tap)).unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    (lucid_auth::axum::router(service.clone()), service)
}

async fn callback(app: &Router, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-tap/callback")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn plugin_is_optional_and_contributes_only_the_official_surface() {
    let config = AuthConfig::new([114_u8; 32]).unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let response = lucid_auth::axum::router(service)
        .oneshot(
            Request::post("/api/auth/one-tap/callback")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "idToken": "token" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let (_, service) = application(Some("google-client"));
    let descriptor = service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "one-tap")
        .unwrap();
    assert_eq!(descriptor.endpoints.len(), 1);
    assert_eq!(descriptor.endpoints[0].path, "/one-tap/callback");
    assert_eq!(descriptor.endpoints[0].client_method, "oneTap");
    assert_eq!(descriptor.client.unwrap().factory, "oneTapClient");
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
    assert!(service.plugin_migrations().is_empty());
}

#[tokio::test]
async fn exact_body_and_direct_errors_match_better_auth() {
    let (without_client, _) = application(None);
    let (status, body) = callback(
        &without_client,
        json!({ "idToken": "not-a-jwt", "unknown": "stripped" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "message": "Google client ID is required for One Tap. Set it on the oneTap plugin (clientId) or on socialProviders.google."
        })
    );

    let (app, _) = application(Some("google-client"));
    let (status, body) = callback(
        &app,
        json!({
            "idToken": "not-a-jwt",
            "callbackURL": "/dashboard",
            "nonce": "ignored-server-side"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({ "message": "invalid id token" }));

    let (status, body) = callback(
        &app,
        json!({
            "idToken": "not-a-jwt",
            "callbackUrl": "https://evil.example"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({ "message": "invalid id token" }));
}

#[tokio::test]
async fn canonical_callback_url_is_trusted_origin_validated() {
    let (app, _) = application(Some("google-client"));
    let (status, body) = callback(
        &app,
        json!({
            "idToken": "not-a-jwt",
            "callbackURL": "https://evil.example/after"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "INVALID_CALLBACK_URL");

    let (status, body) = callback(
        &app,
        json!({ "idToken": "not-a-jwt", "callbackURL": ["/dashboard"] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "code": "BAD_REQUEST",
            "message": "Invalid callbackURL: expected a string"
        })
    );
}

#[tokio::test]
async fn callback_accepts_only_the_upstream_json_media_type() {
    let (app, _) = application(Some("google-client"));
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-tap/callback")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("idToken=not-a-jwt"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (_, body) = {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice::<Value>(&bytes).unwrap())
    };
    assert_eq!(body["code"], "UNSUPPORTED_MEDIA_TYPE");
    assert_eq!(
        body["message"],
        "Content-Type \"application/x-www-form-urlencoded\" is not allowed. Allowed types: application/json"
    );

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-tap/callback")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body,
        json!({
            "code": "UNSUPPORTED_MEDIA_TYPE",
            "message": "Content-Type is required. Allowed types: application/json"
        })
    );
}

#[tokio::test]
async fn callback_matches_upstream_json_parsing_and_validation_order() {
    let (app, _) = application(Some("google-client"));
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-tap/callback")
                .header(header::CONTENT_TYPE, "application/json-patch+json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["code"], "VALIDATION_ERROR");

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-tap/callback")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["code"], "VALIDATION_ERROR");

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-tap/callback")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body,
        json!({ "code": "BAD_REQUEST", "message": "Invalid JSON in request body" })
    );

    let (status, body) = callback(&app, json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
    assert_eq!(
        body["message"],
        "[\n  {\n    \"expected\": \"string\",\n    \"code\": \"invalid_type\",\n    \"path\": [\n      \"idToken\"\n    ],\n    \"message\": \"Invalid input: expected string, received undefined\"\n  }\n]"
    );
}
