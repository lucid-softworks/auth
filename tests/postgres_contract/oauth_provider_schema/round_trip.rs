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
            .create_oauth_resource(resource(resource_id))
            .await?
            .is_some()
    );

    let client_id = "mapped-storage-client";
    let registration = store
        .persist_oauth_client_registration(OAuthClientRegistrationWrite {
            client: client(client_id, user_id),
            resource_ids: vec![resource_id.into()],
            mode: OAuthClientRegistrationMode::Create,
        })
        .await?;
    assert!(matches!(
        registration,
        OAuthClientRegistrationOutcome::Created(_)
    ));
    assert_eq!(store.list_oauth_client_resources(client_id).await?.len(), 1);

    let consent = store
        .upsert_oauth_consent(consent(client_id, user_id))
        .await?;
    assert_eq!(store.find_oauth_consent(consent.id).await?, Some(consent));

    let refresh = refresh("mapped-refresh", client_id, user_id);
    let access = access("mapped-access", client_id, user_id, refresh.id);
    store
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: Some(access.clone()),
            refresh_token: Some(refresh.clone()),
        })
        .await?;
    assert_eq!(
        store.find_oauth_refresh_token(&refresh.token).await?,
        Some(refresh)
    );
    assert_eq!(
        store.find_oauth_access_token(&access.token).await?,
        Some(access)
    );

    let assertion = OAuthProviderClientAssertion {
        id: "mapped-assertion".into(),
        expires_at: now() + Duration::minutes(5),
    };
    assert!(
        store
            .reserve_oauth_client_assertion(assertion.clone())
            .await?
    );
    assert!(!store.reserve_oauth_client_assertion(assertion).await?);
    Ok(())
}
