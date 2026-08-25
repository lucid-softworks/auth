use super::support::*;

pub(super) async fn persist_authorization_client(fixture: &Fixture, client_id: &str) {
    let mut registered = client(client_id, Some(fixture.user_id));
    registered.token_endpoint_auth_method = Some("client_secret_post".into());
    registered.require_pkce = Some(false);
    fixture
        .oauth
        .persist_oauth_client_registration(OAuthClientRegistrationWrite {
            client: registered,
            resource_ids: Vec::new(),
            mode: OAuthClientRegistrationMode::Create,
        })
        .await
        .unwrap();
}

pub(super) fn authorization_query(
    client_id: &str,
    response_type: Option<&str>,
    prompt: Option<&str>,
    claims: Option<&Value>,
) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    if let Some(response_type) = response_type {
        serializer.append_pair("response_type", response_type);
    }
    serializer
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", "https://client.example/callback")
        .append_pair("scope", "openid profile");
    if let Some(prompt) = prompt {
        serializer.append_pair("prompt", prompt);
    }
    if let Some(claims) = claims {
        serializer.append_pair("claims", &claims.to_string());
    }
    serializer.finish()
}

pub(super) async fn assert_authorization_error(
    fixture: &Fixture,
    query: &str,
    expected_base: &str,
    code: &str,
    description: &str,
) {
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
        format!(
            "{}://{}{}",
            location.scheme(),
            location.host_str().unwrap(),
            location.path()
        ),
        expected_base
    );
    let pairs = location
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(pairs["error"], code);
    assert_eq!(pairs["error_description"], description);
}

pub(super) async fn create_client(fixture: &Fixture) -> (String, String) {
    let (status, _, body) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/create-client",
        Some(json!({
            "redirect_uris":["https://client.example/callback"],
            "scope":"openid profile",
            "grant_types":["authorization_code"],
            "response_types":["code"],
            "token_endpoint_auth_method":"client_secret_post"
        })),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (
        body["client_id"].as_str().unwrap().into(),
        body["client_secret"].as_str().unwrap().into(),
    )
}

pub(super) async fn prepare_consent_case() -> (Fixture, String, String, String, String) {
    let fixture = fixture().await;
    let (client_id, client_secret) = create_client(&fixture).await;
    let verifier = "b".repeat(64);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let claims = json!({"userinfo":{"name":null,"email":null}});
    let query = authorization_query_with_pkce(&client_id, &challenge, &claims);
    let oauth_query = authorize_to_consent(&fixture, &query).await;
    (fixture, client_id, client_secret, verifier, oauth_query)
}

pub(super) fn authorization_query_with_pkce(
    client_id: &str,
    challenge: &str,
    claims: &Value,
) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", "https://client.example/callback")
        .append_pair("scope", "openid profile")
        .append_pair("claims", &claims.to_string())
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .finish()
}

pub(super) async fn authorize_to_consent(fixture: &Fixture, query: &str) -> String {
    authorize_to_page(fixture, query, "/consent?").await
}

pub(super) async fn authorize_to_page(fixture: &Fixture, query: &str, page: &str) -> String {
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
    let location = headers[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with(page), "{location}");
    location.split_once('?').unwrap().1.to_owned()
}

pub(super) async fn assert_consent_error(
    fixture: &Fixture,
    oauth_query: &str,
    mut body: Value,
    description: &str,
) {
    body["oauth_query"] = Value::String(oauth_query.into());
    let (status, _, error) = json_request(
        &fixture.app,
        "POST",
        "/api/auth/oauth2/consent",
        Some(body),
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error"], "invalid_request");
    assert_eq!(error["error_description"], description);
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn raw_request(
    fixture: &Fixture,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Body,
    cookie: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, "http://localhost");
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = fixture
        .app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}
