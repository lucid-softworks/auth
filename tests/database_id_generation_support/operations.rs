use super::{CoreFixture, password_user};
use lucid_auth::{AccessStore, ApiKeySortDirection, ApiKeyUpdate, OAuthAccountStore};

pub(super) async fn exercise_read_operations(fixture: &CoreFixture) {
    assert!(
        !fixture
            .service
            .username_available("callback_user")
            .await
            .unwrap()
    );
    assert!(
        fixture
            .service
            .session(&fixture.session_token)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        fixture
            .store
            .list_user_accounts(&fixture.user_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        fixture
            .service
            .list_passkeys(&fixture.user_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(fixture.store.count_users(&[]).await.unwrap(), 1);
    assert_eq!(fixture.store.count_users_by_role("owner").await.unwrap(), 1);
    assert_eq!(
        fixture
            .service
            .list_api_keys(
                &fixture.actor,
                &fixture.configuration,
                None,
                None,
                ApiKeySortDirection::Ascending,
            )
            .await
            .unwrap()
            .len(),
        1
    );
    fixture
        .service
        .get_api_key(&fixture.actor, &fixture.configuration, &fixture.api_key_id)
        .await
        .unwrap();
    fixture
        .service
        .verify_api_key(
            &fixture.api_key_secret,
            std::slice::from_ref(&fixture.configuration),
            Some("default"),
            None,
        )
        .await
        .unwrap();
}

pub(super) async fn exercise_update_operations(fixture: &CoreFixture) {
    fixture
        .service
        .update_api_key(
            &fixture.actor,
            &fixture.configuration,
            &fixture.api_key_id,
            ApiKeyUpdate {
                name: Some("renamed contract key".into()),
                ..ApiKeyUpdate::default()
            },
        )
        .await
        .unwrap();
    fixture
        .service
        .update_verification_value(
            &fixture.verification_identifier,
            "updated-value".into(),
            None,
        )
        .await
        .unwrap()
        .unwrap();
    fixture
        .service
        .consume_rate_limit_request(&fixture.rate_limit_request, Some("192.0.2.100"))
        .await
        .unwrap()
        .unwrap();
    fixture
        .service
        .provision_password_user(password_user("callback_user"))
        .await
        .unwrap();
}

pub(super) async fn exercise_delete_operations(fixture: &CoreFixture) {
    fixture
        .service
        .delete_verification_value(&fixture.verification_identifier)
        .await
        .unwrap()
        .unwrap();
    fixture
        .service
        .delete_api_key(&fixture.actor, &fixture.configuration, &fixture.api_key_id)
        .await
        .unwrap();
    fixture
        .service
        .sign_out(&fixture.session_token)
        .await
        .unwrap();
    assert_eq!(fixture.service.delete_expired_api_keys().await.unwrap(), 0);
}
