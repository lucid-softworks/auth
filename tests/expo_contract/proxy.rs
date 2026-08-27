use super::support::{application, body_json};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::ExpoOptions;
use tower::ServiceExt;

fn proxy(target: &str, oauth_state: Option<&str>) -> Request<Body> {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("authorizationURL", target);
    if let Some(oauth_state) = oauth_state {
        query.append_pair("oauthState", oauth_state);
    }
    Request::builder()
        .uri(format!(
            "/api/auth/expo-authorization-proxy?{}",
            query.finish()
        ))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn proxy_sets_the_exact_raw_and_signed_core_cookies() {
    let (app, service) = application(Some(ExpoOptions::default()));
    let target = "https://provider.example/authorize?client_id=client&state=provider-state";
    let signed = app.clone().oneshot(proxy(target, None)).await.unwrap();
    assert_eq!(signed.status(), StatusCode::FOUND);
    assert_eq!(signed.headers()[header::LOCATION], target);
    let cookie = signed.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("__Secure-better-auth.state="));
    assert!(cookie.contains("; HttpOnly; SameSite=Lax; Path=/; Max-Age=300; Secure"));
    let encoded = cookie.split_once('=').unwrap().1.split(';').next().unwrap();
    assert_eq!(
        service.verify_cookie_value(encoded).as_deref(),
        Some("provider-state")
    );

    let raw = app
        .oneshot(proxy(target, Some("persisted-state")))
        .await
        .unwrap();
    assert_eq!(raw.status(), StatusCode::FOUND);
    assert_eq!(raw.headers()[header::LOCATION], target);
    assert_eq!(
        raw.headers()[header::SET_COOKIE],
        "__Secure-better-auth.oauth_state=persisted-state; HttpOnly; SameSite=Lax; Path=/; Max-Age=600; Secure"
    );
}

#[tokio::test]
async fn proxy_rejects_every_unsafe_authorization_target() {
    let targets = [
        "not-a-url",
        "http://provider.example/authorize?state=x",
        "https://auth.example/api/auth/callback/provider?state=x",
        "https://provider.example/authorize?state=x#fragment",
        "https://provider.example/authorize?state=x#",
    ];
    for target in targets {
        let (app, _) = application(Some(ExpoOptions::default()));
        let response = app.oneshot(proxy(target, None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{target}");
        assert_eq!(
            body_json(response).await,
            serde_json::json!({
                "code": "BAD_REQUEST",
                "message": "Invalid authorizationURL"
            })
        );
    }
}

#[tokio::test]
async fn proxy_requires_state_and_exact_query_casing() {
    let (app, _) = application(Some(ExpoOptions::default()));
    let no_state = app
        .clone()
        .oneshot(proxy("https://provider.example/authorize", None))
        .await
        .unwrap();
    assert_eq!(no_state.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(no_state).await["message"], "Unexpected error");

    let wrong_case = app
        .oneshot(
            Request::builder()
                .uri("/api/auth/expo-authorization-proxy?authorizationUrl=https%3A%2F%2Fprovider.example%2Fauthorize%3Fstate%3Dx")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_case.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(wrong_case).await,
        serde_json::json!({
            "code": "VALIDATION_ERROR",
            "message": "[query.authorizationURL] Invalid input: expected string, received undefined"
        })
    );
}

#[tokio::test]
async fn route_is_absent_without_the_plugin_and_get_only_when_enabled() {
    let (disabled, _) = application(None);
    assert_eq!(
        disabled
            .oneshot(proxy("https://provider.example/?state=x", None))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    let (enabled, _) = application(Some(ExpoOptions::default()));
    let post = enabled
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/expo-authorization-proxy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
}
