use super::support::{application, body_json};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::ExpoOptions;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

static NEXT_EMAIL: AtomicUsize = AtomicUsize::new(1);

fn sign_up(headers: &[(&str, &str)]) -> Request<Body> {
    let email = NEXT_EMAIL.fetch_add(1, Ordering::Relaxed);
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/auth/sign-up/email")
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request
        .body(Body::from(
            json!({
                "email": format!("expo-{email}@example.com"),
                "password": "correct horse battery staple",
                "name": "Expo User"
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn expo_origin_flows_through_the_ordinary_trusted_origin_policy() {
    let (app, _) = application(Some(ExpoOptions::default()));
    let accepted = app
        .clone()
        .oneshot(sign_up(&[("expo-origin", "oracle://")]))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);

    let preserved = app
        .clone()
        .oneshot(sign_up(&[
            (header::ORIGIN.as_str(), "https://evil.example"),
            ("expo-origin", "oracle://"),
        ]))
        .await
        .unwrap();
    assert_eq!(preserved.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(preserved).await["code"], "INVALID_ORIGIN");

    let web = app
        .oneshot(sign_up(&[(header::ORIGIN.as_str(), "https://web.example")]))
        .await
        .unwrap();
    assert_eq!(web.status(), StatusCode::OK);
}

#[tokio::test]
async fn aliases_and_disabled_override_do_not_supply_an_origin() {
    for name in ["expoOrigin", "x-expo-origin", "x-electron-origin"] {
        let (app, _) = application(Some(ExpoOptions::default()));
        let response = app
            .oneshot(sign_up(&[
                (name, "oracle://"),
                ("sec-fetch-site", "same-origin"),
            ]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}");
        assert_eq!(body_json(response).await["code"], "MISSING_OR_NULL_ORIGIN");
    }

    let (app, _) = application(Some(ExpoOptions {
        disable_origin_override: true,
    }));
    let response = app
        .oneshot(sign_up(&[
            ("expo-origin", "oracle://"),
            ("sec-fetch-site", "same-origin"),
        ]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await["code"], "MISSING_OR_NULL_ORIGIN");
}
