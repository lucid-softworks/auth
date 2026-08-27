use super::*;
use crate::{
    AuthConfig, AuthError, AuthService, DatabaseIdGeneration, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerationSize, DatabaseIdGenerator, DatabaseIdInput,
    DatabaseIdPlan, DatabaseIdValue, MemoryStore, PreparedDatabaseId,
    oauth_provider::{
        OAuthCallbackContext, OAuthClientRegistrationMode, OAuthClientRegistrationOutcome,
        OAuthClientRegistrationWrite, OAuthClientResourceLinkOutcome, OAuthProviderAccessToken,
        OAuthProviderAssertionStore, OAuthProviderClient, OAuthProviderClientAssertion,
        OAuthProviderClientResource, OAuthProviderClientStore, OAuthProviderConsent,
        OAuthProviderConsentStore, OAuthProviderPlugin, OAuthProviderPluginConfig,
        OAuthProviderRefreshToken, OAuthProviderResource, OAuthProviderResourceStore,
        OAuthProviderTokenStore, OAuthResourceInput, OAuthTokenIssuance,
    },
};
use chrono::{Duration, Utc};
use std::sync::{Arc, Mutex};

mod database;
mod support;

use support::*;

#[tokio::test]
async fn every_application_strategy_round_trips_all_oauth_records() {
    for strategy in [
        DatabaseIdGeneration::Default,
        DatabaseIdGeneration::Uuid,
        DatabaseIdGeneration::Serial,
    ] {
        let service = service_with_strategy(strategy.clone());
        let ids = create_every_record(&service, &MemoryOAuthProviderStore::new()).await;
        for id in ids {
            match strategy {
                DatabaseIdGeneration::Default => {
                    assert_eq!(id.len(), 32);
                    assert!(id.bytes().all(|byte| byte.is_ascii_alphanumeric()));
                }
                DatabaseIdGeneration::Uuid => {
                    assert_eq!(uuid::Uuid::parse_str(&id).unwrap().to_string(), id);
                }
                DatabaseIdGeneration::Serial => assert_eq!(id, "1"),
                _ => unreachable!(),
            }
        }
    }
}

#[tokio::test]
async fn all_oauth_records_use_canonical_ordinary_callback_ids() {
    let ledger = Arc::new(IdLedger::default());
    let service = service(ledger.clone());
    let store = MemoryOAuthProviderStore::new();
    let ids = create_every_record(&service, &store).await;
    assert_eq!(
        ids,
        [
            "opaque::oauthResource::?/+",
            "opaque::oauthClient::?/+",
            "opaque::oauthClientResource::?/+",
            "opaque::oauthConsent::?/+",
            "opaque::oauthRefreshToken::?/+",
            "opaque::oauthAccessToken::?/+",
            "opaque::oauthClientAssertion::?/+",
        ]
    );

    let calls = ledger.0.lock().unwrap().clone();
    assert_eq!(calls.len(), 7);
    assert!(
        calls
            .iter()
            .all(|(_, size)| *size == DatabaseIdGenerationSize::Omitted)
    );
    assert_eq!(
        calls
            .into_iter()
            .map(|(model, _)| model)
            .collect::<Vec<_>>(),
        [
            "oauthResource",
            "oauthClient",
            "oauthClientResource",
            "oauthConsent",
            "oauthRefreshToken",
            "oauthAccessToken",
            "oauthClientAssertion",
        ]
    );
}

#[tokio::test]
async fn physical_model_remapping_never_changes_the_callback_model() {
    let ledger = Arc::new(IdLedger::default());
    let mut provider_config = OAuthProviderPluginConfig::new("/login", "/consent");
    provider_config.disable_jwt_plugin = true;
    provider_config.schema.oauth_resource.model_name = Some("physicalOAuthResources".into());
    let plugin = OAuthProviderPlugin::new(provider_config, MemoryOAuthProviderStore::new());
    assert_eq!(
        plugin.config().schema.oauth_resource.model_name.as_deref(),
        Some("physicalOAuthResources")
    );
    let admin = plugin.resource_admin();
    let mut config = AuthConfig::new([77_u8; 32]).unwrap();
    config.database_id_generation = DatabaseIdGeneration::Callback(ledger.clone());
    config.add_plugin(plugin).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);

    let created = admin
        .create(
            &service,
            OAuthResourceInput {
                identifier: "https://ids.example/remapped".into(),
                name: Some("Remapped resource".into()),
                access_token_ttl: None,
                refresh_token_ttl: None,
                signing_algorithm: None,
                signing_key_id: None,
                allowed_scopes: None,
                custom_claims: None,
                dpop_bound_access_tokens_required: None,
                disabled: None,
                metadata: None,
            },
            &OAuthCallbackContext {
                session: Some(serde_json::json!({"id": "remap-session"})),
                ..OAuthCallbackContext::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(created.id, "opaque::oauthResource::?/+");
    assert_eq!(
        ledger.0.lock().unwrap().as_slice(),
        &[("oauthResource".into(), DatabaseIdGenerationSize::Omitted)]
    );
}

#[tokio::test]
async fn existing_and_conflict_branches_do_not_prepare_unused_ids() {
    let ledger = Arc::new(IdLedger::default());
    let service = service(ledger);
    let store = MemoryOAuthProviderStore::new();
    create_resource(&service, &store).await;
    let (created_client, link) = create_client_and_link(&service, &store).await;
    let mut consent = create_consent(&service, &store).await;
    let (refresh, access) = create_tokens(&service, &store).await;
    reserve_assertion(&service, &store).await;
    let unexpected = || -> Result<PreparedDatabaseId, AuthError> {
        panic!("a non-insert branch must not prepare an id")
    };

    assert!(
        store
            .create_oauth_resource(&unexpected, resource())
            .await
            .unwrap()
            .is_none()
    );
    let outcome = store
        .persist_oauth_client_registration(
            &unexpected,
            &unexpected,
            OAuthClientRegistrationWrite {
                client: client(),
                resource_ids: vec![resource().identifier],
                mode: OAuthClientRegistrationMode::Create,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        OAuthClientRegistrationOutcome::ClientIdTaken
    ));
    let outcome = store
        .link_oauth_client_resource(&unexpected, link)
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        OAuthClientResourceLinkOutcome::AlreadyLinked(_)
    ));

    consent.updated_at = Utc::now();
    let updated = store
        .upsert_oauth_consent(&unexpected, consent.clone())
        .await
        .unwrap();
    assert_eq!(updated.id, consent.id);
    assert!(
        store
            .issue_oauth_tokens(
                &unexpected,
                &unexpected,
                OAuthTokenIssuance {
                    refresh_token: Some(refresh),
                    access_token: Some(access),
                },
            )
            .await
            .is_err()
    );
    assert!(
        !store
            .reserve_oauth_client_assertion(
                &unexpected,
                OAuthProviderClientAssertion {
                    id: String::new(),
                    jti: "protocol-jti-digest".into(),
                    expires_at: Utc::now() + Duration::minutes(5),
                },
            )
            .await
            .unwrap()
    );
    assert_eq!(created_client.id, "opaque::oauthClient::?/+");
}
