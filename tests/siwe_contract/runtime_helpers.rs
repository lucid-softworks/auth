use super::*;

#[tokio::test]
async fn duplicate_nonce_generation_and_request_origin_fallback_match_upstream() {
    let (app, _) = application("repeat01");
    assert_sequential_and_concurrent_nonce_generation(&app).await;

    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([124_u8; 32]).unwrap();
    config.use_secure_cookies = Some(true);
    let siwe = SiweConfig::new(
        "auth.example",
        Arc::new(Nonce("origin01")),
        Arc::new(Verifier),
    );
    config
        .add_plugin(SiwePlugin::new(store.clone(), siwe))
        .unwrap();
    let app = lucid_auth::axum::router(Arc::new(AuthService::new(store.clone(), config)));
    create_nonce_with_host(&app, "auth.example").await;
    let response = app
        .oneshot(
            Request::post("/api/auth/siwe/verify")
                .header(header::HOST, "auth.example")
                .header("x-forwarded-host", "attacker.example")
                .header("x-forwarded-proto", "http")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "message":message("origin01", "auth.example"),
                        "signature":"signed"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        store
            .find_user_by_email(&format!("{ADDRESS}@https://auth.example"))
            .await
            .unwrap()
            .is_some()
    );
    assert_trusted_proxy_origin().await;
}

async fn assert_trusted_proxy_origin() {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([128_u8; 32]).unwrap();
    config.trusted_proxy_headers = true;
    let siwe = SiweConfig::new(
        "auth.example",
        Arc::new(Nonce("proxy001")),
        Arc::new(Verifier),
    );
    config
        .add_plugin(SiwePlugin::new(store.clone(), siwe))
        .unwrap();
    let app = lucid_auth::axum::router(Arc::new(AuthService::new(store.clone(), config)));
    create_nonce_with_host(&app, "internal.example").await;
    let response = app
        .oneshot(
            Request::post("/api/auth/siwe/verify")
                .header(header::HOST, "internal.example")
                .header("x-forwarded-host", "public.example")
                .header("x-forwarded-proto", "https")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "message":message("proxy001", "auth.example"),
                        "signature":"signed"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        store
            .find_user_by_email(&format!("{ADDRESS}@https://public.example"))
            .await
            .unwrap()
            .is_some()
    );
}

async fn assert_sequential_and_concurrent_nonce_generation(app: &Router) {
    for content_type in [None, Some("application/json-patch+json")] {
        let mut request = Request::post("/api/auth/siwe/nonce");
        let body = if content_type.is_some() { "{}" } else { "" };
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let request = || {
        Request::post("/api/auth/siwe/nonce")
            .body(Body::empty())
            .unwrap()
    };
    let (left, right) = tokio::join!(
        app.clone().oneshot(request()),
        app.clone().oneshot(request())
    );
    assert_eq!(left.unwrap().status(), StatusCode::OK);
    assert_eq!(right.unwrap().status(), StatusCode::OK);
}

async fn create_nonce_with_host(app: &Router, host: &str) {
    app.clone()
        .oneshot(
            Request::post("/api/auth/siwe/nonce")
                .header(header::HOST, host)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn stateless_siwe_emits_the_session_cache_cookie_once() {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([127_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config.session.storage_mode = SessionStorageMode::Stateless;
    config.session.cookie_cache.enabled = true;
    let siwe = SiweConfig::new(
        "example.com",
        Arc::new(Nonce("cache001")),
        Arc::new(Verifier),
    );
    config
        .add_plugin(SiwePlugin::new(store.clone(), siwe))
        .unwrap();
    let app = lucid_auth::axum::router(Arc::new(AuthService::new(store, config)));
    create_nonce_with_host(&app, "example.com").await;
    let response = app
        .oneshot(
            Request::post("/api/auth/siwe/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "message":message("cache001", "example.com"),
                        "signature":"signed"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.contains("better-auth.session_token="))
    );
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.contains("better-auth.session_data="))
    );
}
