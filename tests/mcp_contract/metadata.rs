use super::support::*;

const CACHE_CONTROL: &str = "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400";

#[tokio::test]
async fn both_protected_resource_aliases_match_rfc_9728_wire_behavior() {
    let app = app();
    let expected = json!({
        "resource": RESOURCE,
        "authorization_servers": ["http://localhost/api/auth"],
        "bearer_methods_supported": ["header"],
        "dpop_signing_alg_values_supported": ["EdDSA", "ES256", "ES512", "PS256", "RS256"],
        "scopes_supported": ["mcp.read"],
    });
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let (status, headers, body) = request(&app, "GET", path).await;
        assert_eq!(status, StatusCode::OK, "GET {path}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(headers[header::CACHE_CONTROL], CACHE_CONTROL);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), expected);

        let (status, headers, body) = request(&app, "HEAD", path).await;
        assert_eq!(status, StatusCode::OK, "HEAD {path}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(headers[header::CACHE_CONTROL], CACHE_CONTROL);
        assert!(body.is_empty());

        let (status, headers, body) = request(&app, "POST", path).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "POST {path}");
        assert_eq!(headers[header::ALLOW], "GET, HEAD");
        assert!(body.is_empty());
    }
}

#[tokio::test]
async fn metadata_aliases_are_root_mounted_and_unrelated_paths_fall_through() {
    let app = app();
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/auth/.well-known/oauth-protected-resource"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "GET", "/.well-known/oauth-protected-resource/other")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn trailing_slash_aliases_follow_the_global_advanced_option() {
    let mut config = AuthConfig::new([206_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.skip_trailing_slashes = true;
    config.add_plugin(JwtPlugin::default()).unwrap();
    config.add_plugin(plugin()).unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    let app = lucid_auth::axum::router(service);

    for path in [
        "/.well-known/oauth-protected-resource///",
        "/.well-known/oauth-protected-resource/mcp///",
    ] {
        assert_eq!(request(&app, "GET", path).await.0, StatusCode::OK, "{path}");
    }
}
