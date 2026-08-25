use super::support::*;

#[tokio::test]
async fn authorization_errors_use_only_trusted_redirects_and_allow_loopback_port_variance() {
    let fixture = fixture().await;
    register_loopback_client(&fixture).await;
    assert_trusted_loopback_error(&fixture).await;
    assert_untrusted_error_fallback(&fixture).await;
}

async fn register_loopback_client(fixture: &Fixture) {
    let mut redirect_client = client("redirect-contract", Some(fixture.user_id));
    redirect_client.redirect_uris = vec!["http://127.0.0.1/callback".into()];
    fixture
        .oauth
        .persist_oauth_client_registration(OAuthClientRegistrationWrite {
            client: redirect_client,
            resource_ids: Vec::new(),
            mode: OAuthClientRegistrationMode::Create,
        })
        .await
        .unwrap();
}

async fn assert_trusted_loopback_error(fixture: &Fixture) {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", "redirect-contract")
        .append_pair("redirect_uri", "http://127.0.0.1:43123/callback")
        .append_pair("scope", "openid")
        .append_pair("state", "trusted-state")
        .append_pair("code_challenge", "challenge-without-method")
        .finish();
    let (status, headers, _) = request(
        &fixture.app,
        "GET",
        &format!("/api/auth/oauth2/authorize?{query}"),
        None,
        Body::empty(),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let location = Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        location.origin().ascii_serialization(),
        "http://127.0.0.1:43123"
    );
    assert_eq!(location.path(), "/callback");
    let pairs = location
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(pairs["error"], "invalid_request");
    assert_eq!(pairs["state"], "trusted-state");
    assert_eq!(pairs["iss"], "http://localhost/api/auth");
}

async fn assert_untrusted_error_fallback(fixture: &Fixture) {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", "missing-client")
        .append_pair("redirect_uri", "https://attacker.example/callback")
        .finish();
    let (status, headers, _) = request(
        &fixture.app,
        "GET",
        &format!("/api/auth/oauth2/authorize?{query}"),
        None,
        Body::empty(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let location = Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        location.as_str().split('?').next().unwrap(),
        "http://localhost/api/auth/error"
    );
    let pairs = location
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(pairs["error"], "invalid_client");
    assert!(!pairs.contains_key("state") && !pairs.contains_key("iss"));
}

#[tokio::test]
async fn authorization_consent_pkce_exchange_and_refresh_replay_work_end_to_end() {
    let fixture = fixture().await;
    let (client_id, client_secret) = create_confidential_client(&fixture).await;
    let (code, verifier) = authorize_and_consent(&fixture, &client_id).await;
    exchange_and_replay_refresh(&fixture, &client_id, &client_secret, &code, &verifier).await;
}

async fn create_confidential_client(fixture: &Fixture) -> (String, String) {
    let (status, _, created) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "redirect_uris": ["https://client.example/callback"],
            "scope": "openid profile offline_access",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post"
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    (
        created["client_id"].as_str().unwrap().to_owned(),
        created["client_secret"].as_str().unwrap().to_owned(),
    )
}

async fn authorize_and_consent(fixture: &Fixture, client_id: &str) -> (String, String) {
    let verifier = "a".repeat(64);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", "https://client.example/callback")
        .append_pair("scope", "openid profile offline_access")
        .append_pair("state", "contract-state")
        .append_pair("nonce", "contract-nonce")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let (status, headers, _) = request(
        &fixture.app,
        "GET",
        &format!("/api/auth/oauth2/authorize?{query}"),
        None,
        Body::empty(),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let consent_location = headers[header::LOCATION].to_str().unwrap();
    assert!(consent_location.starts_with("/consent?"));
    let oauth_query = consent_location.split_once('?').unwrap().1;
    let (status, _, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/consent",
        Some(json!({ "accept": true, "oauth_query": oauth_query })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["redirect"], true);
    let callback = Url::parse(body["url"].as_str().unwrap()).unwrap();
    let pairs = callback
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(pairs["state"], "contract-state");
    assert_eq!(pairs["iss"], "http://localhost/api/auth");
    (pairs["code"].to_string(), verifier)
}

async fn exchange_and_replay_refresh(
    fixture: &Fixture,
    client_id: &str,
    client_secret: &str,
    code: &str,
    verifier: &str,
) {
    let (status, _, tokens) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", "https://client.example/callback"),
            ("code_verifier", verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(tokens["access_token"].is_string() && tokens["id_token"].is_string());
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let request = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("refresh_token", refresh),
    ];
    let (status, _, rotated) = form_request(&fixture.app, "/api/auth/oauth2/token", &request).await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    let (status, _, replayed) =
        form_request(&fixture.app, "/api/auth/oauth2/token", &request).await;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(replayed["access_token"], rotated["access_token"]);
    assert_eq!(replayed["refresh_token"], rotated["refresh_token"]);
}
