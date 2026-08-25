use super::support::*;

#[tokio::test]
async fn logout_without_hint_requires_signed_browser_confirmation() {
    let fixture = fixture().await;
    register_logout_client(&fixture).await;
    issue_logout_tokens(&fixture).await;
    let query = logout_query(false);
    let (status, headers, body) = navigation_request(
        &fixture,
        "GET",
        &format!("/api/auth/oauth2/end-session?{query}"),
        None,
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains("Confirm logout"));
    assert!(
        fixture
            .service
            .session(&fixture.raw_session_token)
            .await
            .unwrap()
            .is_some()
    );
    let confirmation = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value
                .starts_with("better-auth.session_token.oauth_logout_confirmation=")
                .then(|| value.split(';').next().unwrap().to_owned())
        })
        .expect("confirmation cookie");
    assert!(
        headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("form-action 'self'")
    );

    let cookies = format!("{}; {confirmation}", fixture.cookie);
    let (status, headers, confirm_body) = navigation_request(
        &fixture,
        "POST",
        "/api/auth/oauth2/end-session/confirm",
        Some("action=confirm"),
        Some(&cookies),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "{}",
        String::from_utf8_lossy(&confirm_body)
    );
    assert_eq!(
        headers[header::LOCATION],
        "https://client.example/logged-out?state=state-1"
    );
    assert_logout_revocations(&fixture).await;
}

#[tokio::test]
async fn verified_hint_logs_out_directly_and_post_body_overrides_query() {
    let fixture = fixture().await;
    register_logout_client(&fixture).await;
    let hint = signed_hint(&fixture).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", &hint)
        .append_pair("state", "body-state")
        .finish();
    let query = logout_query(false);
    let (status, headers, _) = request(
        &fixture.app,
        "POST",
        &format!("/api/auth/oauth2/end-session?{query}"),
        Some("application/x-www-form-urlencoded"),
        Body::from(body),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        headers[header::LOCATION],
        "https://client.example/logged-out?state=body-state"
    );
    assert!(
        fixture
            .service
            .session(&fixture.raw_session_token)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn fetch_without_hint_does_not_delete_the_session() {
    let fixture = fixture().await;
    let (status, _, body) = json_request(
        &fixture.app,
        "GET",
        "/api/auth/oauth2/end-session",
        None,
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(
        fixture
            .service
            .session(&fixture.raw_session_token)
            .await
            .unwrap()
            .is_some()
    );
}

type LogoutCapture = Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<String>>>>;

async fn capture_logout(
    axum::extract::State(capture): axum::extract::State<LogoutCapture>,
    body: String,
) -> StatusCode {
    if let Some(sender) = capture.lock().unwrap().take() {
        let _ = sender.send(body);
    }
    StatusCode::NO_CONTENT
}

#[tokio::test]
async fn session_deletion_posts_logout_jwt_and_preserves_offline_refresh() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let capture = Arc::new(std::sync::Mutex::new(Some(sender)));
    let callback = Router::new()
        .route("/logout", axum::routing::post(capture_logout))
        .with_state(capture);
    let server = tokio::spawn(async move { axum::serve(listener, callback).await.unwrap() });

    let fixture = fixture().await;
    let mut logout_client = client("logout-client", Some(fixture.user_id));
    logout_client.backchannel_logout_uri = Some(format!("http://{address}/logout"));
    fixture
        .oauth
        .persist_oauth_client_registration(OAuthClientRegistrationWrite {
            client: logout_client,
            resource_ids: Vec::new(),
            mode: OAuthClientRegistrationMode::Create,
        })
        .await
        .unwrap();
    issue_logout_tokens(&fixture).await;
    fixture
        .service
        .sign_out(&fixture.raw_session_token)
        .await
        .unwrap();

    let body = receiver.await.unwrap();
    let form =
        serde_urlencoded::from_str::<std::collections::BTreeMap<String, String>>(&body).unwrap();
    let token = form.get("logout_token").expect("logout token");
    assert_eq!(
        jsonwebtoken::decode_header(token).unwrap().typ.as_deref(),
        Some("logout+jwt")
    );
    let claims = jsonwebtoken::dangerous::insecure_decode::<Value>(token)
        .unwrap()
        .claims;
    assert_eq!(claims["aud"], "logout-client");
    assert_eq!(claims["sid"], fixture.session_id.to_string());
    let events = claims["events"].as_object().unwrap();
    assert_eq!(events.len(), 1);
    assert!(events["http://schemas.openid.net/event/backchannel-logout"].is_object());
    assert_logout_revocations(&fixture).await;
    server.abort();
}

async fn register_logout_client(fixture: &Fixture) {
    let mut logout_client = client("logout-client", Some(fixture.user_id));
    logout_client.enable_end_session = Some(true);
    logout_client.post_logout_redirect_uris = Some(vec![
        "https://client.example/logged-out?existing=kept".into(),
        "https://client.example/logged-out".into(),
    ]);
    fixture
        .oauth
        .persist_oauth_client_registration(OAuthClientRegistrationWrite {
            client: logout_client,
            resource_ids: Vec::new(),
            mode: OAuthClientRegistrationMode::Create,
        })
        .await
        .unwrap();
}

async fn signed_hint(fixture: &Fixture) -> String {
    fixture
        .service
        .jwt()
        .unwrap()
        .sign_jwt(
            &JwtAdapterContext::default(),
            Map::from_iter([
                ("iss".into(), json!("http://localhost/api/auth")),
                ("aud".into(), json!("logout-client")),
                ("sub".into(), json!(fixture.user_id)),
                ("sid".into(), json!(fixture.session_id)),
            ]),
            Some(JwtProtectedHeader::default()),
            JwtSigningOverrides::default(),
        )
        .await
        .unwrap()
}

async fn issue_logout_tokens(fixture: &Fixture) {
    let online_id = Uuid::new_v4();
    fixture
        .oauth
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: Some(access_token(
                "logout-access",
                "logout-client",
                fixture.user_id,
                Some(fixture.session_id),
                Some(online_id),
            )),
            refresh_token: Some(refresh_token(
                online_id,
                "logout-online",
                "logout-client",
                fixture.user_id,
                Some(fixture.session_id),
                vec!["profile".into()],
            )),
        })
        .await
        .unwrap();
    fixture
        .oauth
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: None,
            refresh_token: Some(refresh_token(
                Uuid::new_v4(),
                "logout-offline",
                "logout-client",
                fixture.user_id,
                Some(fixture.session_id),
                vec!["offline_access".into()],
            )),
        })
        .await
        .unwrap();
}

fn logout_query(with_hint: bool) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("client_id", "logout-client")
        .append_pair(
            "post_logout_redirect_uri",
            "https://client.example/logged-out",
        )
        .append_pair("state", "state-1");
    if with_hint {
        query.append_pair("id_token_hint", "unused");
    }
    query.finish()
}

async fn navigation_request(
    fixture: &Fixture,
    method: &str,
    path: &str,
    form: Option<&str>,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::ACCEPT, "text/html")
        .header("sec-fetch-mode", "navigate");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if form.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    let response = fixture
        .app
        .clone()
        .oneshot(
            request
                .body(form.map_or_else(Body::empty, |form| Body::from(form.to_owned())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

async fn assert_logout_revocations(fixture: &Fixture) {
    assert!(
        fixture
            .service
            .session(&fixture.raw_session_token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .oauth
            .find_oauth_access_token("logout-access")
            .await
            .unwrap()
            .unwrap()
            .revoked
            .is_some()
    );
    assert!(
        fixture
            .oauth
            .find_oauth_refresh_token("logout-online")
            .await
            .unwrap()
            .unwrap()
            .revoked
            .is_some()
    );
    assert!(
        fixture
            .oauth
            .find_oauth_refresh_token("logout-offline")
            .await
            .unwrap()
            .unwrap()
            .revoked
            .is_none()
    );
}
