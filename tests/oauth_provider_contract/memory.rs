use super::support::*;

#[tokio::test]
async fn memory_store_registration_issuance_and_rotation_are_atomic() {
    let store = Arc::new(MemoryOAuthProviderStore::new());
    let user_id = Uuid::new_v4();
    assert_registration_race(&store, user_id).await;
    assert_rotation_race(&store, user_id).await;
    assert_issuance_rollback(&store, user_id).await;
}

async fn assert_registration_race(store: &MemoryOAuthProviderStore, user_id: Uuid) {
    let registration = OAuthClientRegistrationWrite {
        client: client("atomic-client", Some(user_id)),
        resource_ids: Vec::new(),
        mode: OAuthClientRegistrationMode::Create,
    };
    let (left, right) = tokio::join!(
        store.persist_oauth_client_registration(registration.clone()),
        store.persist_oauth_client_registration(registration)
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, OAuthClientRegistrationOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, OAuthClientRegistrationOutcome::ClientIdTaken))
            .count(),
        1
    );
}

async fn assert_rotation_race(store: &MemoryOAuthProviderStore, user_id: Uuid) {
    let previous_id = Uuid::new_v4();
    store
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: None,
            refresh_token: Some(refresh_token(
                previous_id,
                "previous-refresh",
                "atomic-client",
                user_id,
                None,
                vec!["offline_access".into()],
            )),
        })
        .await
        .unwrap();
    let rotation = |suffix: &str| OAuthRefreshRotation {
        previous_refresh_id: previous_id,
        rotated_at: Utc::now(),
        replay_expires_at: Some(Utc::now() + Duration::seconds(30)),
        next_refresh_token: refresh_token(
            Uuid::new_v4(),
            &format!("next-{suffix}"),
            "atomic-client",
            user_id,
            None,
            vec!["offline_access".into()],
        ),
        access_token: None,
    };
    let (left, right) = tokio::join!(
        store.rotate_oauth_refresh_token(rotation("left")),
        store.rotate_oauth_refresh_token(rotation("right"))
    );
    let outcomes = [left.unwrap(), right.unwrap()];
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
}

async fn assert_issuance_rollback(store: &MemoryOAuthProviderStore, user_id: Uuid) {
    let duplicate_access = access_token("duplicate-access", "atomic-client", user_id, None, None);
    store
        .issue_oauth_tokens(OAuthTokenIssuance {
            access_token: Some(duplicate_access.clone()),
            refresh_token: None,
        })
        .await
        .unwrap();
    let rolled_back_refresh = refresh_token(
        Uuid::new_v4(),
        "must-not-persist",
        "atomic-client",
        user_id,
        None,
        vec!["offline_access".into()],
    );
    assert!(
        store
            .issue_oauth_tokens(OAuthTokenIssuance {
                access_token: Some(duplicate_access),
                refresh_token: Some(rolled_back_refresh),
            })
            .await
            .is_err()
    );
    assert!(
        store
            .find_oauth_refresh_token("must-not-persist")
            .await
            .unwrap()
            .is_none()
    );
}
