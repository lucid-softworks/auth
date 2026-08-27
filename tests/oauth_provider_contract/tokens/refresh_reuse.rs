use super::*;

#[tokio::test]
async fn mismatched_reuse_inside_the_interval_does_not_revoke_the_family() {
    let fixture = fixture().await;
    let (client_id, client_secret) = create_refresh_client(&fixture).await;
    let original = "refresh-reuse-original";
    let stored = URL_SAFE_NO_PAD.encode(Sha256::digest(original.as_bytes()));
    fixture
        .oauth
        .issue_oauth_tokens(
            &oauth_record_id,
            &oauth_record_id,
            OAuthTokenIssuance {
                access_token: None,
                refresh_token: Some(refresh_token(
                    String::new(),
                    &stored,
                    &client_id,
                    &fixture.user_id,
                    Some(&fixture.session_id),
                    vec!["openid".into(), "profile".into(), "offline_access".into()],
                )),
            },
        )
        .await
        .unwrap();

    let (status, _, rotated) = refresh(&fixture, &client_id, &client_secret, original, None).await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    let rotated_token = rotated["refresh_token"].as_str().unwrap().to_owned();

    let (status, _, mismatch) = refresh(
        &fixture,
        &client_id,
        &client_secret,
        original,
        Some("profile offline_access"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{mismatch}");
    assert_eq!(mismatch["error"], "invalid_grant");

    let (status, _, still_active) =
        refresh(&fixture, &client_id, &client_secret, &rotated_token, None).await;
    assert_eq!(status, StatusCode::OK, "{still_active}");
}

async fn create_refresh_client(fixture: &Fixture) -> (String, String) {
    let (status, _, created) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "redirect_uris": ["https://client.example/callback"],
            "scope": "openid profile offline_access",
            "grant_types": ["authorization_code", "refresh_token"],
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

async fn refresh(
    fixture: &Fixture,
    client_id: &str,
    client_secret: &str,
    token: &str,
    scope: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let mut values = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("refresh_token", token),
    ];
    if let Some(scope) = scope {
        values.push(("scope", scope));
    }
    form_request(&fixture.app, "/api/auth/oauth2/token", &values).await
}
