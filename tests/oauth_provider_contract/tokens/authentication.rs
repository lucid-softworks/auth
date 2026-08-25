use super::*;

#[tokio::test]
async fn endpoint_authentication_cardinality_and_scheme_handling_match_upstream() {
    let fixture = fixture().await;
    let (client_id, client_secret) = create_m2m_client(&fixture).await;
    let (status, _, error) = form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["error"], "invalid_request");
    assert_eq!(error["error_description"], "client_id must not be repeated");

    let mut stored = fixture
        .oauth
        .find_oauth_client(&client_id)
        .await
        .unwrap()
        .unwrap();
    stored.token_endpoint_auth_method = Some("client_secret_basic".into());
    fixture.oauth.update_oauth_client(stored).await.unwrap();

    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"));
    let (status, _, token) = authorized_form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &format!("bAsIc {basic}"),
        &[("grant_type", "client_credentials"), ("scope", "api.read")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{token}");

    let (status, _, error) = authorized_form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        &format!("Basic {basic}"),
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["error"], "invalid_request");
    assert_eq!(
        error["error_description"],
        "A request must use only one client authentication method"
    );

    let (status, headers, error) = authorized_form_request(
        &fixture.app,
        "/api/auth/oauth2/token",
        "Bearer unsupported",
        &[("grant_type", "client_credentials")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{error}");
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(error["error"], "invalid_client");
}

#[tokio::test]
async fn public_none_clients_can_revoke_but_cannot_introspect_and_inactive_userinfo_challenges() {
    let fixture = fixture().await;
    let public_id = "public-contract-client";
    fixture
        .oauth
        .persist_oauth_client_registration(OAuthClientRegistrationWrite {
            client: client(public_id, Some(fixture.user_id)),
            resource_ids: Vec::new(),
            mode: OAuthClientRegistrationMode::Create,
        })
        .await
        .unwrap();
    let raw_access = "public-contract-access";
    let stored_access = URL_SAFE_NO_PAD.encode(Sha256::digest(raw_access.as_bytes()));
    fixture
        .oauth
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: Some(access_token(
                &stored_access,
                public_id,
                fixture.user_id,
                None,
                None,
            )),
            refresh_token: None,
        })
        .await
        .unwrap();
    let (status, _, error) = form_request(
        &fixture.app,
        "/api/auth/oauth2/introspect",
        &[("client_id", public_id), ("token", raw_access)],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{error}");
    assert_eq!(error["error"], "invalid_client");

    let prefixed = format!("dPoP {raw_access}");
    let (status, _, body) = form_request(
        &fixture.app,
        "/api/auth/oauth2/revoke",
        &[("client_id", public_id), ("token", &prefixed)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        fixture
            .oauth
            .find_oauth_access_token(&stored_access)
            .await
            .unwrap()
            .is_none()
    );

    let (status, headers, error) = authorized_form_request(
        &fixture.app,
        "/api/auth/oauth2/userinfo",
        &format!("bEaReR {raw_access}"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{error}");
    assert_eq!(error["error"], "invalid_token");
    assert_eq!(error["error_description"], "Invalid access token");
    assert_eq!(
        headers[header::WWW_AUTHENTICATE],
        "Bearer error=\"invalid_token\", error_description=\"Invalid access token\""
    );
}

#[tokio::test]
async fn refresh_introspection_includes_issuer_and_strips_token_scheme_case_insensitively() {
    let fixture = fixture().await;
    let (client_id, client_secret) = create_m2m_client(&fixture).await;
    let raw_refresh = "contract-refresh-token";
    let stored_refresh = URL_SAFE_NO_PAD.encode(Sha256::digest(raw_refresh.as_bytes()));
    fixture
        .oauth
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: None,
            refresh_token: Some(refresh_token(
                Uuid::new_v4(),
                &stored_refresh,
                &client_id,
                fixture.user_id,
                None,
                vec!["api.read".into()],
            )),
        })
        .await
        .unwrap();
    let presented = format!("bEaReR {raw_refresh}");
    let (status, _, active) = form_request(
        &fixture.app,
        "/api/auth/oauth2/introspect",
        &[
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("token", &presented),
            ("token_type_hint", "refresh_token"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(active["active"], true);
    assert_eq!(active["iss"], "http://localhost/api/auth");
}
