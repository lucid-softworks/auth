use super::{support::*, *};

#[tokio::test]
async fn database_strategy_reaches_every_real_oauth_create_boundary() {
    let service = service_with_strategy(DatabaseIdGeneration::Database);
    assert_database_resource(&service).await;
    assert_database_client(&service).await;
    assert_database_link(&service).await;
    assert_database_consent(&service).await;
    assert_database_tokens(&service).await;
    assert_database_assertion(&service).await;
}

async fn assert_database_resource(service: &AuthService) {
    let id = plan(service, "oauthResource");
    let error = MemoryOAuthProviderStore::new()
        .create_oauth_resource(&|| service.prepare_database_id(&id), resource())
        .await
        .unwrap_err();
    assert_deferred_model(error, "oauthResource");
}

async fn assert_database_client(service: &AuthService) {
    let client_id = plan(service, "oauthClient");
    let link_id = plan(service, "oauthClientResource");
    let error = MemoryOAuthProviderStore::new()
        .persist_oauth_client_registration(
            &|| service.prepare_database_id(&client_id),
            &|| service.prepare_database_id(&link_id),
            OAuthClientRegistrationWrite {
                client: client(),
                resource_ids: Vec::new(),
                mode: OAuthClientRegistrationMode::Create,
            },
        )
        .await
        .unwrap_err();
    assert_deferred_model(error, "oauthClient");
}

async fn assert_database_link(service: &AuthService) {
    let store = MemoryOAuthProviderStore::new();
    let seed_id = || {
        Ok(PreparedDatabaseId::Value(DatabaseIdValue::String(
            "seed-record".into(),
        )))
    };
    store
        .persist_oauth_client_registration(
            &seed_id,
            &seed_id,
            OAuthClientRegistrationWrite {
                client: client(),
                resource_ids: Vec::new(),
                mode: OAuthClientRegistrationMode::Create,
            },
        )
        .await
        .unwrap();
    let mut linked_resource = resource();
    linked_resource.identifier = "https://ids.example/linked".into();
    store
        .create_oauth_resource(&seed_id, linked_resource)
        .await
        .unwrap()
        .unwrap();
    let id = plan(service, "oauthClientResource");
    let error = store
        .link_oauth_client_resource(
            &|| service.prepare_database_id(&id),
            OAuthProviderClientResource {
                id: String::new(),
                client_id: "id-client".into(),
                resource_id: "https://ids.example/linked".into(),
                metadata: None,
                created_at: Some(Utc::now()),
            },
        )
        .await
        .unwrap_err();
    assert_deferred_model(error, "oauthClientResource");
}

async fn assert_database_consent(service: &AuthService) {
    let id = plan(service, "oauthConsent");
    let now = Utc::now();
    let error = MemoryOAuthProviderStore::new()
        .upsert_oauth_consent(
            &|| service.prepare_database_id(&id),
            OAuthProviderConsent {
                id: String::new(),
                client_id: "database-client".into(),
                user_id: Some("database-user".into()),
                reference_id: None,
                resources: None,
                requested_user_info_claims: None,
                scopes: vec!["openid".into()],
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap_err();
    assert_deferred_model(error, "oauthConsent");
}

async fn assert_database_tokens(service: &AuthService) {
    let store = MemoryOAuthProviderStore::new();
    let (refresh, mut access) = token_records();
    let refresh_id = plan(service, "oauthRefreshToken");
    let access_id = plan(service, "oauthAccessToken");
    let error = store
        .issue_oauth_tokens(
            &|| service.prepare_database_id(&refresh_id),
            &|| service.prepare_database_id(&access_id),
            OAuthTokenIssuance {
                refresh_token: Some(refresh),
                access_token: None,
            },
        )
        .await
        .unwrap_err();
    assert_deferred_model(error, "oauthRefreshToken");

    access.refresh_id = None;
    let error = store
        .issue_oauth_tokens(
            &|| service.prepare_database_id(&refresh_id),
            &|| service.prepare_database_id(&access_id),
            OAuthTokenIssuance {
                refresh_token: None,
                access_token: Some(access),
            },
        )
        .await
        .unwrap_err();
    assert_deferred_model(error, "oauthAccessToken");
}

async fn assert_database_assertion(service: &AuthService) {
    let id = plan(service, "oauthClientAssertion");
    let error = MemoryOAuthProviderStore::new()
        .reserve_oauth_client_assertion(
            &|| service.prepare_database_id(&id),
            OAuthProviderClientAssertion {
                id: String::new(),
                jti: "database-jti-digest".into(),
                expires_at: Utc::now() + Duration::minutes(5),
            },
        )
        .await
        .unwrap_err();
    assert_deferred_model(error, "oauthClientAssertion");
}

fn assert_deferred_model(error: AuthError, model: &str) {
    assert!(
        matches!(error, AuthError::Storage(message) if message.contains(&format!("model '{model}'")))
    );
}
