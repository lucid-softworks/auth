use super::{fixtures::*, *};
use lucid_auth::{
    OAuthProviderAssertionStore, OAuthProviderClientAssertion, OAuthProviderClientStore,
    OAuthProviderTokenStore, OAuthRefreshRotation, OAuthRefreshRotationOutcome, OAuthTokenIssuance,
    VerificationValue,
};

pub(super) async fn one_time_operations(
    service: &AuthService,
    store: &PostgresOAuthProviderStore,
) -> Result<(), Box<dyn std::error::Error>> {
    authorization_code_consumption(service).await?;
    assertion_reservation(store).await?;
    refresh_rotation_and_issuance_rollback(service, store).await
}

async fn authorization_code_consumption(
    service: &AuthService,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = now();
    service
        .create_verification_value(VerificationValue::new(
            "concurrent-code",
            serde_json::json!({"type": "authorization_code"}).to_string(),
            now + Duration::minutes(10),
        ))
        .await?;
    let (left, right) = tokio::join!(
        service.consume_verification_value("concurrent-code", now),
        service.consume_verification_value("concurrent-code", now),
    );
    assert_eq!(
        usize::from(left?.is_some()) + usize::from(right?.is_some()),
        1
    );
    Ok(())
}

async fn assertion_reservation(
    store: &PostgresOAuthProviderStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let assertion = OAuthProviderClientAssertion {
        id: "concurrent-assertion".into(),
        expires_at: now() + Duration::minutes(5),
    };
    let (left, right) = tokio::join!(
        store.reserve_oauth_client_assertion(assertion.clone()),
        store.reserve_oauth_client_assertion(assertion),
    );
    assert_eq!(usize::from(left?) + usize::from(right?), 1);
    Ok(())
}

async fn refresh_rotation_and_issuance_rollback(
    service: &AuthService,
    store: &PostgresOAuthProviderStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let user_id = provision_user(service).await?;
    let client_id = "mapped-atomic-client";
    store
        .persist_oauth_client_registration(lucid_auth::OAuthClientRegistrationWrite {
            client: client(client_id, user_id),
            resource_ids: Vec::new(),
            mode: lucid_auth::OAuthClientRegistrationMode::Create,
        })
        .await?;

    let original = refresh("atomic-original", client_id, user_id);
    let existing_access = access("atomic-access", client_id, user_id, original.id);
    store
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: Some(existing_access.clone()),
            refresh_token: Some(original.clone()),
        })
        .await?;
    assert_issuance_rolls_back(store, client_id, user_id, existing_access).await?;
    assert_rotation_is_compare_and_swap(store, client_id, user_id, original.id).await
}

async fn assert_issuance_rolls_back(
    store: &PostgresOAuthProviderStore,
    client_id: &str,
    user_id: Uuid,
    duplicate_access: lucid_auth::OAuthProviderAccessToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidate = refresh("must-not-persist", client_id, user_id);
    assert!(
        store
            .issue_oauth_tokens(OAuthTokenIssuance {
                access_token: Some(duplicate_access),
                refresh_token: Some(candidate),
            })
            .await
            .is_err()
    );
    assert!(
        store
            .find_oauth_refresh_token("must-not-persist")
            .await?
            .is_none()
    );
    Ok(())
}

async fn assert_rotation_is_compare_and_swap(
    store: &PostgresOAuthProviderStore,
    client_id: &str,
    user_id: Uuid,
    previous_refresh_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let rotation = |suffix: &str| OAuthRefreshRotation {
        previous_refresh_id,
        rotated_at: now(),
        replay_expires_at: Some(now() + Duration::seconds(30)),
        next_refresh_token: refresh(&format!("atomic-next-{suffix}"), client_id, user_id),
        access_token: None,
    };
    let (left, right) = tokio::join!(
        store.rotate_oauth_refresh_token(rotation("left")),
        store.rotate_oauth_refresh_token(rotation("right")),
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, OAuthRefreshRotationOutcome::Rotated(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, OAuthRefreshRotationOutcome::AlreadyConsumed(_)))
            .count(),
        1
    );
    Ok(())
}
