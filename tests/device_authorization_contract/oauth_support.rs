use super::support::*;
use lucid_auth::{
    JwtConfig, JwtPlugin, MemoryOAuthProviderStore, OAuthClientRegistrationMode,
    OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite, OAuthDeviceAuthorizationPlugin,
    OAuthProviderClientStore, OAuthProviderPlugin, OAuthProviderPluginConfig,
    OAuthProviderResource, OAuthProviderResourceStore,
};

pub(super) const CLIENT_ID: &str = "device-client";
pub(super) const RESOURCE: &str = "https://device.example/resource";

pub(super) struct OAuthFixture {
    pub(super) app: Router,
    pub(super) devices: Arc<MemoryDeviceAuthorizationStore>,
    pub(super) cookie: String,
    pub(super) user_id: String,
}

pub(super) async fn oauth_fixture() -> OAuthFixture {
    let devices = Arc::new(MemoryDeviceAuthorizationStore::new());
    let oauth = Arc::new(MemoryOAuthProviderStore::new());
    oauth
        .create_oauth_resource(resource())
        .await
        .unwrap()
        .expect("resource is created");
    let mut registered = oauth_client();
    registered.user_id = None;
    assert!(matches!(
        oauth
            .persist_oauth_client_registration(OAuthClientRegistrationWrite {
                client: registered,
                resource_ids: vec![RESOURCE.into()],
                mode: OAuthClientRegistrationMode::Create,
            })
            .await
            .unwrap(),
        OAuthClientRegistrationOutcome::Created(_)
    ));

    let mut auth = AuthConfig::new([212_u8; 32]).unwrap();
    auth.set_base_url("http://localhost/api/auth").unwrap();
    auth.add_plugin(JwtPlugin::new(JwtConfig::default()))
        .unwrap();
    auth.add_plugin(OAuthProviderPlugin::from_arc(
        OAuthProviderPluginConfig::new("/login", "/consent"),
        oauth,
    ))
    .unwrap();
    let mut device_config = DeviceAuthorizationConfig::default();
    device_config.interval = "0s".into();
    auth.add_plugin(OAuthDeviceAuthorizationPlugin::from_arc(
        device_config,
        devices.clone() as Arc<_>,
    ))
    .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), auth).unwrap());
    service
        .provision_password_user(NewPasswordUser {
            username: "oauth_device_owner".into(),
            name: "OAuth Device Owner".into(),
            email: Some("oauth-device-owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username(
            "oauth_device_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&signed_in.token)
    );
    OAuthFixture {
        app: lucid_auth::axum::router(service),
        devices,
        cookie,
        user_id: signed_in.session.user.id,
    }
}

fn oauth_client() -> lucid_auth::OAuthProviderClient {
    let now = Utc::now();
    lucid_auth::OAuthProviderClient {
        id: Uuid::new_v4(),
        client_id: CLIENT_ID.into(),
        client_secret: None,
        client_discovery_id: None,
        disabled: false,
        skip_consent: None,
        enable_end_session: None,
        subject_type: None,
        scopes: Some(vec!["openid".into(), "profile".into()]),
        client_credentials_scopes: Vec::new(),
        user_id: None,
        created_at: Some(now),
        updated_at: Some(now),
        expires_at: None,
        name: Some("Device client".into()),
        uri: None,
        icon: None,
        contacts: None,
        tos: None,
        policy: None,
        software_id: None,
        software_version: None,
        software_statement: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        token_endpoint_auth_method: Some("none".into()),
        application_type: Some("native".into()),
        jwks: None,
        jwks_uri: None,
        grant_types: Some(vec![GRANT.into()]),
        response_types: Some(Vec::new()),
        require_pkce: Some(false),
        dpop_bound_access_tokens: false,
        reference_id: None,
        metadata: None,
    }
}

fn resource() -> OAuthProviderResource {
    OAuthProviderResource {
        id: Uuid::new_v4(),
        identifier: RESOURCE.into(),
        name: "Device resource".into(),
        access_token_ttl: None,
        refresh_token_ttl: None,
        signing_algorithm: None,
        signing_key_id: None,
        allowed_scopes: Some(vec!["openid".into(), "profile".into()]),
        custom_claims: None,
        dpop_bound_access_tokens_required: false,
        disabled: false,
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        policy_version: 1,
        metadata: None,
    }
}

pub(super) fn oauth_record(
    device_code: &str,
    user_code: &str,
    user_id: Option<String>,
    status: DeviceCodeStatus,
) -> DeviceCode {
    let mut record = record(device_code, user_code, user_id, status);
    record.client_id = None;
    record.oauth_client_id = Some(CLIENT_ID.into());
    record.resources = Some(vec![RESOURCE.into()]);
    record.scope = Some("openid profile".into());
    record
}

pub(super) async fn oauth_issue(app: &Router, body: Value) -> Value {
    let (status, _, body) = json_request(app, "POST", "/api/auth/device/code", body, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

pub(super) async fn oauth_token(
    app: &Router,
    parameters: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Value) {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("grant_type", GRANT);
    serializer.extend_pairs(parameters.iter().copied());
    let (status, headers, bytes) = request(
        app,
        "POST",
        "/api/auth/oauth2/token",
        Some("application/x-www-form-urlencoded"),
        Body::from(serializer.finish()),
        None,
    )
    .await;
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
