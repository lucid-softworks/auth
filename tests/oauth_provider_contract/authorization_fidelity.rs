use super::authorization_support::*;
use super::support::*;

#[tokio::test]
async fn authorization_post_rejects_non_form_media_types_exactly() {
    let fixture = fixture().await;
    let (status, headers, body) = raw_request(
        &fixture,
        "POST",
        "/api/auth/oauth2/authorize",
        Some("application/json"),
        Body::from("{}"),
        None,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert!(!headers.contains_key(header::CACHE_CONTROL));
    assert!(!headers.contains_key(header::PRAGMA));
    assert_eq!(
        body,
        json!({
            "message": "Content-Type \"application/json\" is not allowed. Allowed types: application/x-www-form-urlencoded",
            "code": "UNSUPPORTED_MEDIA_TYPE"
        })
    );
}

#[tokio::test]
async fn authorization_redirects_are_json_typed() {
    let fixture = fixture().await;
    let (status, headers, _) = request(
        &fixture.app,
        "GET",
        "/api/auth/oauth2/authorize",
        None,
        Body::empty(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert!(headers.contains_key(header::LOCATION));
}

#[tokio::test]
async fn authorization_response_issuer_uses_the_normalized_jwt_issuer() {
    let mut jwt = JwtConfig::default();
    jwt.jwt.issuer = Some("http://issuer.example/custom?discarded=yes#fragment".into());
    let provider = OAuthProviderPluginConfig::new("/login", "/consent");
    let fixture = fixture_with_jwt_and_provider(jwt, provider).await;
    persist_authorization_client(&fixture, "issuer-client").await;
    let query = authorization_query("issuer-client", None, None, None);
    let (_, headers, _) = request(
        &fixture.app,
        "GET",
        &format!("/api/auth/oauth2/authorize?{query}"),
        None,
        Body::empty(),
        Some(&fixture.cookie),
    )
    .await;
    let location = Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        location
            .query_pairs()
            .find(|(name, _)| name == "iss")
            .unwrap()
            .1,
        "https://issuer.example/custom"
    );
}

#[tokio::test]
async fn response_type_and_prompt_errors_match_the_pinned_provider() {
    let fixture = fixture().await;
    persist_authorization_client(&fixture, "syntax-client").await;

    let missing = authorization_query("syntax-client", None, None, None);
    assert_authorization_error(
        &fixture,
        &missing,
        "https://client.example/callback",
        "invalid_request",
        "response_type is required",
    )
    .await;

    let unsupported = authorization_query("syntax-client", Some("token"), None, None);
    assert_authorization_error(
        &fixture,
        &unsupported,
        "http://localhost/api/auth/error",
        "unsupported_response_type",
        "unsupported response type",
    )
    .await;

    for (prompt, description) in [
        (" ", "prompt: prompt must include at least one value"),
        ("login bogus", "prompt: unsupported prompt value: bogus"),
        (
            "none login",
            "prompt: prompt=none cannot be combined with other prompt values",
        ),
    ] {
        let query = authorization_query("syntax-client", Some("code"), Some(prompt), None);
        assert_authorization_error(
            &fixture,
            &query,
            "https://client.example/callback",
            "invalid_request",
            description,
        )
        .await;
    }

    let select = authorization_query("syntax-client", Some("code"), Some("select_account"), None);
    assert_authorization_error(
        &fixture,
        &select,
        "http://localhost/api/auth/error",
        "unsupported_prompt_select_account",
        "unsupported prompt type",
    )
    .await;
}

#[tokio::test]
async fn oidc_claims_shape_and_essential_acr_match_the_pinned_provider() {
    let fixture = fixture().await;
    persist_authorization_client(&fixture, "claims-client").await;
    for invalid in [json!(null), json!([]), json!({"userinfo":{"email":true}})] {
        let query = authorization_query("claims-client", Some("code"), None, Some(&invalid));
        assert_authorization_error(
            &fixture,
            &query,
            "https://client.example/callback",
            "invalid_request",
            "claims must be a valid Claims request object",
        )
        .await;
    }
    let essential = json!({"id_token":{"acr":{"essential":true,"value":"urn:unsupported"}}});
    let query = authorization_query("claims-client", Some("code"), None, Some(&essential));
    assert_authorization_error(
        &fixture,
        &query,
        "https://client.example/callback",
        "access_denied",
        "essential acr requirement cannot be met",
    )
    .await;
}

#[tokio::test]
async fn authorize_uses_json_redirect_envelopes_for_fetch_and_accept_json() {
    let fixture = fixture().await;
    persist_authorization_client(&fixture, "response-client").await;
    let query = authorization_query("response-client", None, None, None);
    for (name, value) in [
        (header::ACCEPT.as_str(), "application/json"),
        ("sec-fetch-mode", "cors"),
    ] {
        let response = raw_request(
            &fixture,
            "GET",
            &format!("/api/auth/oauth2/authorize?{query}"),
            None,
            Body::empty(),
            Some(&fixture.cookie),
            &[(name, value)],
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.2["redirect"], true);
        let url = Url::parse(response.2["url"].as_str().unwrap()).unwrap();
        assert_eq!(
            url.query_pairs()
                .find(|(name, _)| name == "error")
                .unwrap()
                .1,
            "invalid_request"
        );
    }
}

#[tokio::test]
async fn consent_rejects_scope_claim_widening_and_invalid_claims() {
    let (fixture, _, _, _, oauth_query) = prepare_consent_case().await;
    assert_consent_error(
        &fixture,
        &oauth_query,
        json!({"accept":true,"scope":"admin"}),
        "Scope not originally requested",
    )
    .await;
    assert_consent_error(
        &fixture,
        &oauth_query,
        json!({"accept":true,"claims":{"userinfo":{"picture":null}}}),
        "Claim not originally requested",
    )
    .await;
    assert_consent_error(
        &fixture,
        &oauth_query,
        json!({"accept":true,"claims":[]}),
        "claims must be a valid Claims request object",
    )
    .await;
}

#[tokio::test]
async fn consent_rewrites_narrowed_scope_and_claims_into_the_code() {
    let (fixture, client_id, client_secret, verifier, oauth_query) = prepare_consent_case().await;
    let (status, _, accepted) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/consent",
        Some(json!({
            "accept": true,
            "scope": "openid",
            "claims": {"userinfo":{"name":null}},
            "oauth_query": oauth_query,
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(accepted["redirect"], true);
    let callback = Url::parse(accepted["url"].as_str().unwrap()).unwrap();
    let code = callback
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("code", &code),
            ("redirect_uri", "https://client.example/callback"),
            ("code_verifier", &verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["scope"], "openid");

    let stored_access = URL_SAFE_NO_PAD.encode(Sha256::digest(
        tokens["access_token"].as_str().unwrap().as_bytes(),
    ));
    let access = fixture
        .oauth
        .find_oauth_access_token(&stored_access)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(access.requested_user_info_claims.unwrap(), ["name"]);
}

#[tokio::test]
async fn continue_accepts_only_post_login_casing_and_clears_completed_authentication() {
    let fixture = fixture().await;
    persist_authorization_client(&fixture, "continue-client").await;
    let query = authorization_query("continue-client", Some("code"), Some("login"), None);
    let signed = authorize_to_page(&fixture, &query, "/login?").await;
    let signed_in = fixture
        .service
        .sign_in_username(
            "oauth_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let fresh_cookie = format!(
        "better-auth.session_token={}",
        fixture.service.signed_cookie_value(&signed_in.token)
    );

    let (status, _, wrong) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/continue",
        Some(json!({"post_login":true,"oauth_query":signed})),
        Some(&fresh_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong["error_description"], "Missing parameters");

    let (status, _, continued) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/continue",
        Some(json!({"postLogin":true,"oauth_query":signed})),
        Some(&fresh_cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{continued}");
    assert!(continued["url"].as_str().unwrap().starts_with("/consent?"));
}
