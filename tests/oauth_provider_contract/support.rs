pub(super) use async_trait::async_trait;
pub(super) use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
pub(super) use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub(super) use chrono::{Duration, Utc};
pub(super) use http_body_util::BodyExt;
pub(super) use lucid_auth::{
    AuthConfig, AuthError, AuthPlugin, AuthService, DatabaseIdValue, JwtAdapterContext, JwtConfig,
    JwtPlugin, JwtProtectedHeader, JwtSigningOverrides, MemoryOAuthProviderStore, MemoryStore,
    NewPasswordUser, OAuthCallbackContext, OAuthClaimTarget, OAuthClientRegistrationMode,
    OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite, OAuthExpiration,
    OAuthExtensionClientAuthentication, OAuthExtensionClientAuthenticationInput,
    OAuthExtensionClientAuthenticationMethod, OAuthExtensionGrantInput, OAuthProviderAccessToken,
    OAuthProviderApiAuthenticationRequest, OAuthProviderApiRequest,
    OAuthProviderApiTokenIssueInput, OAuthProviderClient, OAuthProviderClientAssertionInput,
    OAuthProviderClientResource, OAuthProviderClientStore, OAuthProviderConfigError,
    OAuthProviderExtension, OAuthProviderMetadataDocument, OAuthProviderPlugin,
    OAuthProviderPluginConfig, OAuthProviderRefreshToken, OAuthProviderResource,
    OAuthProviderResourceStore, OAuthProviderTokenStore, OAuthRefreshRotation,
    OAuthRefreshRotationOutcome, OAuthTokenIssuance, PreparedDatabaseId,
};
pub(super) use serde_json::{Map, Value, json};
pub(super) use sha2::{Digest as _, Sha256};
pub(super) use std::sync::Arc;
pub(super) use tower::ServiceExt;
pub(super) use url::Url;
pub(super) use uuid::Uuid;

pub(super) fn oauth_record_id() -> Result<PreparedDatabaseId, AuthError> {
    Ok(PreparedDatabaseId::Value(DatabaseIdValue::String(
        Uuid::new_v4().to_string(),
    )))
}

pub(super) struct Fixture {
    pub(super) app: Router,
    pub(super) service: Arc<AuthService>,
    pub(super) oauth: Arc<MemoryOAuthProviderStore>,
    pub(super) cookie: String,
    pub(super) session_id: String,
    pub(super) user_id: String,
    pub(super) raw_session_token: String,
}

pub(super) async fn fixture() -> Fixture {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.allow_dynamic_client_registration = true;
    provider.allow_unauthenticated_client_registration = true;
    provider.refresh_token_reuse_interval = 30;
    provider.scopes.push("api.read".into());
    fixture_with_provider(provider).await
}

pub(super) async fn fixture_with_provider(provider: OAuthProviderPluginConfig) -> Fixture {
    fixture_with_jwt_and_provider(JwtConfig::default(), provider).await
}

pub(super) async fn fixture_with_jwt_and_provider(
    jwt: JwtConfig,
    provider: OAuthProviderPluginConfig,
) -> Fixture {
    let oauth = Arc::new(MemoryOAuthProviderStore::new());
    let mut config = AuthConfig::new([137_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(JwtPlugin::new(jwt)).unwrap();
    config
        .add_plugin(OAuthProviderPlugin::from_arc(
            provider,
            oauth.clone() as Arc<_>,
        ))
        .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    service
        .provision_password_user(NewPasswordUser {
            username: "oauth_owner".into(),
            name: "OAuth Owner".into(),
            email: Some("oauth-owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username(
            "oauth_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let raw_session_token = signed_in.token;
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&raw_session_token)
    );
    let session_id = signed_in.session.session.id;
    let user_id = signed_in.session.user.id;
    let app = lucid_auth::axum::router(service.clone());
    Fixture {
        app,
        service,
        oauth,
        cookie,
        session_id,
        user_id,
        raw_session_token,
    }
}

pub(super) async fn request(
    app: &Router,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: impl Into<Body>,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, "http://localhost");
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(body.into()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body.to_vec())
}

pub(super) async fn json_request(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let (status, headers, bytes) = request(
        app,
        method,
        path,
        body.as_ref().map(|_| "application/json"),
        body.map_or_else(Body::empty, |value| Body::from(value.to_string())),
        cookie,
    )
    .await;
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

pub(super) async fn form_request(
    app: &Router,
    path: &str,
    pairs: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Value) {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(pairs.iter().copied());
    let (status, headers, bytes) = request(
        app,
        "POST",
        path,
        Some("application/x-www-form-urlencoded"),
        Body::from(serializer.finish()),
        None,
    )
    .await;
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

pub(super) async fn authorized_form_request(
    app: &Router,
    path: &str,
    authorization: &str,
    pairs: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Value) {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(pairs.iter().copied());
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from(serializer.finish()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, headers, body)
}

pub(super) fn client(client_id: &str, user_id: Option<&str>) -> OAuthProviderClient {
    let now = Utc::now();
    OAuthProviderClient {
        id: String::new(),
        client_id: client_id.into(),
        client_secret: None,
        client_discovery_id: None,
        disabled: false,
        skip_consent: None,
        enable_end_session: None,
        subject_type: None,
        scopes: Some(vec![
            "openid".into(),
            "profile".into(),
            "offline_access".into(),
        ]),
        client_credentials_scopes: Vec::new(),
        user_id: user_id.map(str::to_owned),
        created_at: Some(now),
        updated_at: Some(now),
        expires_at: None,
        name: Some("Contract client".into()),
        uri: None,
        icon: None,
        contacts: None,
        tos: None,
        policy: None,
        software_id: None,
        software_version: None,
        software_statement: None,
        redirect_uris: vec!["https://client.example/callback".into()],
        post_logout_redirect_uris: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        token_endpoint_auth_method: Some("none".into()),
        application_type: Some("web".into()),
        jwks: None,
        jwks_uri: None,
        grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        response_types: Some(vec!["code".into()]),
        require_pkce: Some(true),
        dpop_bound_access_tokens: false,
        reference_id: None,
        metadata: None,
    }
}

pub(super) fn refresh_token(
    id: String,
    token: &str,
    client_id: &str,
    user_id: &str,
    session_id: Option<&str>,
    scopes: Vec<String>,
) -> OAuthProviderRefreshToken {
    let now = Utc::now();
    OAuthProviderRefreshToken {
        id,
        token: token.into(),
        client_id: client_id.into(),
        session_id: session_id.map(str::to_owned),
        user_id: user_id.to_owned(),
        reference_id: None,
        authorization_code_id: None,
        resources: None,
        requested_user_info_claims: None,
        expires_at: now + Duration::hours(1),
        created_at: now,
        revoked: None,
        rotated_at: None,
        rotation_replay_response: None,
        rotation_replay_expires_at: None,
        auth_time: Some(now),
        confirmation: None,
        scopes,
    }
}

pub(super) fn access_token(
    token: &str,
    client_id: &str,
    user_id: &str,
    session_id: Option<&str>,
    refresh_id: Option<String>,
) -> OAuthProviderAccessToken {
    let now = Utc::now();
    OAuthProviderAccessToken {
        id: String::new(),
        token: token.into(),
        client_id: client_id.into(),
        session_id: session_id.map(str::to_owned),
        user_id: Some(user_id.to_owned()),
        reference_id: None,
        authorization_code_id: None,
        resources: None,
        requested_user_info_claims: None,
        refresh_id,
        expires_at: now + Duration::hours(1),
        created_at: now,
        revoked: None,
        confirmation: None,
        scopes: vec!["profile".into()],
    }
}
