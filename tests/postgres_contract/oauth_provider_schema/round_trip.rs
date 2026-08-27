use super::{fixtures::*, *};
use lucid_auth::{
    OAuthClientRegistrationMode, OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite,
    OAuthProviderAssertionStore, OAuthProviderClientAssertion, OAuthProviderClientStore,
    OAuthProviderConsentStore, OAuthProviderResourceStore, OAuthProviderTokenStore,
    OAuthTokenIssuance,
};

pub(super) async fn all_seven_models(
    service: &AuthService,
    store: &PostgresOAuthProviderStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let user_id = provision_user(service).await?;
    let resource_id = "https://api.example";
    assert!(
        store
            .create_oauth_resource(
                &|| prepare_oauth_id(service, "oauthResource"),
                resource(resource_id),
            )
            .await?
            .is_some()
    );

    let client_id = "mapped-storage-client";
    let registration = store
        .persist_oauth_client_registration(
            &|| prepare_oauth_id(service, "oauthClient"),
            &|| prepare_oauth_id(service, "oauthClientResource"),
            OAuthClientRegistrationWrite {
                client: client(client_id, &user_id),
                resource_ids: vec![resource_id.into()],
                mode: OAuthClientRegistrationMode::Create,
            },
        )
        .await?;
    assert!(matches!(
        registration,
        OAuthClientRegistrationOutcome::Created(_)
    ));
    assert_eq!(store.list_oauth_client_resources(client_id).await?.len(), 1);

    let consent = store
        .upsert_oauth_consent(
            &|| prepare_oauth_id(service, "oauthConsent"),
            consent(client_id, &user_id),
        )
        .await?;
    assert_eq!(store.find_oauth_consent(&consent.id).await?, Some(consent));

    let refresh = refresh("mapped-refresh", client_id, &user_id);
    let access = access("mapped-access", client_id, &user_id, &refresh.id);
    store
        .issue_oauth_tokens(
            &|| prepare_oauth_id(service, "oauthRefreshToken"),
            &|| prepare_oauth_id(service, "oauthAccessToken"),
            OAuthTokenIssuance {
                access_token: Some(access.clone()),
                refresh_token: Some(refresh.clone()),
            },
        )
        .await?;
    let stored_refresh = store
        .find_oauth_refresh_token(&refresh.token)
        .await?
        .unwrap();
    let stored_access = store.find_oauth_access_token(&access.token).await?.unwrap();
    assert!(!stored_refresh.id.is_empty());
    assert!(!stored_access.id.is_empty());
    assert_eq!(
        stored_access.refresh_id.as_deref(),
        Some(stored_refresh.id.as_str())
    );

    assertion_round_trip(service, store).await?;
    Ok(())
}

async fn assertion_round_trip(
    service: &AuthService,
    store: &PostgresOAuthProviderStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let assertion = OAuthProviderClientAssertion {
        id: String::new(),
        jti: "mapped-assertion".into(),
        expires_at: now() + Duration::minutes(5),
    };
    assert!(
        store
            .reserve_oauth_client_assertion(
                &|| prepare_oauth_id(service, "oauthClientAssertion"),
                assertion.clone(),
            )
            .await?
    );
    assert!(
        !store
            .reserve_oauth_client_assertion(
                &|| prepare_oauth_id(service, "oauthClientAssertion"),
                assertion,
            )
            .await?
    );
    Ok(())
}
