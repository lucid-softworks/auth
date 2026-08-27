use super::*;

#[derive(Debug, Default)]
pub(super) struct IdLedger(pub(super) Mutex<Vec<(String, DatabaseIdGenerationSize)>>);

impl DatabaseIdGenerator for IdLedger {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        self.0
            .lock()
            .unwrap()
            .push((request.model.into(), request.size));
        DatabaseIdGenerationResult::Id(format!("opaque::{}::?/+", request.model))
    }
}

pub(super) fn service(ledger: Arc<IdLedger>) -> AuthService {
    service_with_strategy(DatabaseIdGeneration::Callback(ledger))
}

pub(super) fn service_with_strategy(strategy: DatabaseIdGeneration) -> AuthService {
    let mut config = AuthConfig::new([76_u8; 32]).unwrap();
    config.database_id_generation = strategy;
    AuthService::new(Arc::new(MemoryStore::default()), config)
}

pub(super) fn plan(service: &AuthService, model: &'static str) -> DatabaseIdPlan {
    service.database_id_plan(model, DatabaseIdInput::Absent, false)
}

pub(super) fn resource() -> OAuthProviderResource {
    OAuthProviderResource {
        id: String::new(),
        identifier: "https://ids.example/resource".into(),
        name: "ID resource".into(),
        access_token_ttl: None,
        refresh_token_ttl: None,
        signing_algorithm: None,
        signing_key_id: None,
        allowed_scopes: None,
        custom_claims: None,
        dpop_bound_access_tokens_required: false,
        disabled: false,
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        policy_version: 1,
        metadata: None,
    }
}

pub(super) fn client() -> OAuthProviderClient {
    OAuthProviderClient {
        id: String::new(),
        client_id: "id-client".into(),
        client_secret: None,
        client_discovery_id: None,
        disabled: false,
        skip_consent: None,
        enable_end_session: None,
        subject_type: None,
        scopes: None,
        client_credentials_scopes: Vec::new(),
        user_id: Some("opaque::user::?/+".into()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        expires_at: None,
        name: None,
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
        application_type: Some("web".into()),
        jwks: None,
        jwks_uri: None,
        grant_types: None,
        response_types: None,
        require_pkce: None,
        dpop_bound_access_tokens: false,
        reference_id: None,
        metadata: None,
    }
}

pub(super) async fn create_resource(
    service: &AuthService,
    store: &MemoryOAuthProviderStore,
) -> OAuthProviderResource {
    let id = plan(service, "oauthResource");
    store
        .create_oauth_resource(&|| service.prepare_database_id(&id), resource())
        .await
        .unwrap()
        .unwrap()
}

pub(super) async fn create_client_and_link(
    service: &AuthService,
    store: &MemoryOAuthProviderStore,
) -> (OAuthProviderClient, OAuthProviderClientResource) {
    let client_id = plan(service, "oauthClient");
    let link_id = plan(service, "oauthClientResource");
    let outcome = store
        .persist_oauth_client_registration(
            &|| service.prepare_database_id(&client_id),
            &|| service.prepare_database_id(&link_id),
            OAuthClientRegistrationWrite {
                client: client(),
                resource_ids: vec![resource().identifier],
                mode: OAuthClientRegistrationMode::Create,
            },
        )
        .await
        .unwrap();
    let OAuthClientRegistrationOutcome::Created(client) = outcome else {
        panic!("expected a created client, got {outcome:?}");
    };
    let link = store
        .list_oauth_client_resources(&client.client_id)
        .await
        .unwrap()
        .remove(0);
    (client, link)
}

pub(super) async fn create_consent(
    service: &AuthService,
    store: &MemoryOAuthProviderStore,
) -> OAuthProviderConsent {
    let now = Utc::now();
    let id = plan(service, "oauthConsent");
    store
        .upsert_oauth_consent(
            &|| service.prepare_database_id(&id),
            OAuthProviderConsent {
                id: String::new(),
                client_id: "id-client".into(),
                user_id: Some("opaque::user::?/+".into()),
                reference_id: None,
                resources: None,
                requested_user_info_claims: None,
                scopes: vec!["openid".into()],
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap()
}

pub(super) async fn create_tokens(
    service: &AuthService,
    store: &MemoryOAuthProviderStore,
) -> (OAuthProviderRefreshToken, OAuthProviderAccessToken) {
    let refresh_id = plan(service, "oauthRefreshToken");
    let access_id = plan(service, "oauthAccessToken");
    let (refresh, access) = token_records();
    store
        .issue_oauth_tokens(
            &|| service.prepare_database_id(&refresh_id),
            &|| service.prepare_database_id(&access_id),
            OAuthTokenIssuance {
                refresh_token: Some(refresh),
                access_token: Some(access),
            },
        )
        .await
        .unwrap();
    (
        store
            .find_oauth_refresh_token("refresh-secret")
            .await
            .unwrap()
            .unwrap(),
        store
            .find_oauth_access_token("access-secret")
            .await
            .unwrap()
            .unwrap(),
    )
}

pub(super) fn token_records() -> (OAuthProviderRefreshToken, OAuthProviderAccessToken) {
    let now = Utc::now();
    let refresh = OAuthProviderRefreshToken {
        id: String::new(),
        token: "refresh-secret".into(),
        client_id: "id-client".into(),
        session_id: Some("opaque::session::?/+".into()),
        user_id: "opaque::user::?/+".into(),
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
        scopes: vec!["openid".into()],
    };
    let access = OAuthProviderAccessToken {
        id: String::new(),
        token: "access-secret".into(),
        client_id: "id-client".into(),
        session_id: Some("opaque::session::?/+".into()),
        user_id: Some("opaque::user::?/+".into()),
        reference_id: None,
        authorization_code_id: None,
        resources: None,
        requested_user_info_claims: None,
        refresh_id: Some(String::new()),
        expires_at: now + Duration::minutes(5),
        created_at: now,
        revoked: None,
        confirmation: None,
        scopes: vec!["openid".into()],
    };
    (refresh, access)
}

pub(super) async fn reserve_assertion(
    service: &AuthService,
    store: &MemoryOAuthProviderStore,
) -> String {
    let id = plan(service, "oauthClientAssertion");
    store
        .reserve_oauth_client_assertion(
            &|| service.prepare_database_id(&id),
            OAuthProviderClientAssertion {
                id: String::new(),
                jti: "protocol-jti-digest".into(),
                expires_at: Utc::now() + Duration::minutes(5),
            },
        )
        .await
        .unwrap();
    store
        .state
        .read()
        .await
        .client_assertions
        .get("protocol-jti-digest")
        .unwrap()
        .id
        .clone()
}

pub(super) async fn create_every_record(
    service: &AuthService,
    store: &MemoryOAuthProviderStore,
) -> Vec<String> {
    let resource = create_resource(service, store).await;
    let (client, link) = create_client_and_link(service, store).await;
    let consent = create_consent(service, store).await;
    let (refresh, access) = create_tokens(service, store).await;
    let assertion = reserve_assertion(service, store).await;
    assert_eq!(access.refresh_id.as_deref(), Some(refresh.id.as_str()));
    vec![
        resource.id,
        client.id,
        link.id,
        consent.id,
        refresh.id,
        access.id,
        assertion,
    ]
}
