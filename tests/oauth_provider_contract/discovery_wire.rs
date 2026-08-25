use super::support::*;
use lucid_auth::JwtConfig;

#[tokio::test]
async fn custom_issuer_path_controls_all_discovery_aliases() {
    let mut jwt = JwtConfig::default();
    jwt.jwt.issuer = Some("https://issuer.example/tenant/".into());
    let provider = OAuthProviderPluginConfig::new("/login", "/consent");
    let fixture = fixture_with_jwt_and_provider(jwt, provider).await;

    for path in [
        "/.well-known/oauth-authorization-server/tenant",
        "/tenant/.well-known/oauth-authorization-server",
        "/tenant/.well-known/openid-configuration",
    ] {
        let (status, headers, metadata) = json_request(&fixture.app, "GET", path, None, None).await;
        assert_eq!(status, StatusCode::OK, "GET {path}: {metadata}");
        assert_eq!(metadata["issuer"], "https://issuer.example/tenant");
        assert_eq!(
            headers[header::CACHE_CONTROL],
            "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"
        );
    }
}

#[tokio::test]
async fn metadata_method_rejection_advertises_get_and_head() {
    let fixture = fixture().await;
    let (status, headers, body) = request(
        &fixture.app,
        "POST",
        "/.well-known/oauth-authorization-server/api/auth",
        Some("application/json"),
        Body::from("{}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers[header::ALLOW], "GET,HEAD");
    assert!(body.is_empty());
}

#[tokio::test]
async fn json_endpoints_reject_form_media_with_the_better_call_envelope() {
    let fixture = fixture().await;
    for path in [
        "/api/auth/oauth2/consent",
        "/api/auth/oauth2/continue",
        "/api/auth/oauth2/register",
        "/api/auth/oauth2/create-client",
        "/api/auth/oauth2/public-client-prelogin",
        "/api/auth/oauth2/update-client",
        "/api/auth/oauth2/client/rotate-secret",
        "/api/auth/oauth2/delete-client",
        "/api/auth/oauth2/update-consent",
        "/api/auth/oauth2/delete-consent",
    ] {
        let (status, headers, body) = request(
            &fixture.app,
            "POST",
            path,
            Some("application/x-www-form-urlencoded"),
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "POST {path}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        assert!(!headers.contains_key(header::CACHE_CONTROL), "POST {path}");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({
                "message": "Content-Type \"application/x-www-form-urlencoded\" is not allowed. Allowed types: application/json",
                "code": "UNSUPPORTED_MEDIA_TYPE"
            }),
            "POST {path}"
        );
    }
}

#[tokio::test]
async fn logout_confirmation_is_form_only() {
    let fixture = fixture().await;
    let (status, headers, body) = request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/end-session/confirm",
        Some("application/json"),
        Body::from(r#"{"action":"confirm"}"#),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert!(!headers.contains_key(header::CACHE_CONTROL));
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({
            "message": "Content-Type \"application/json\" is not allowed. Allowed types: application/x-www-form-urlencoded",
            "code": "UNSUPPORTED_MEDIA_TYPE"
        })
    );
}
