use super::MemoryOAuthProviderStore;
use crate::{AuthError, oauth_provider::*};
use chrono::{Duration, Utc};

fn test_id() -> Result<crate::PreparedDatabaseId, AuthError> {
    Ok(crate::PreparedDatabaseId::Value(
        crate::DatabaseIdValue::String(uuid::Uuid::new_v4().to_string()),
    ))
}

fn refresh(token: &str, user_id: &str) -> OAuthProviderRefreshToken {
    OAuthProviderRefreshToken {
        id: String::new(),
        token: token.into(),
        client_id: "client".into(),
        session_id: None,
        user_id: user_id.to_owned(),
        reference_id: None,
        authorization_code_id: None,
        resources: None,
        requested_user_info_claims: None,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked: None,
        rotated_at: None,
        rotation_replay_response: None,
        rotation_replay_expires_at: None,
        auth_time: None,
        confirmation: None,
        scopes: vec!["offline_access".into()],
    }
}

#[tokio::test]
async fn refresh_rotation_is_compare_and_swap() {
    let store = MemoryOAuthProviderStore::new();
    let user_id = "opaque-user::?/+";
    let original = refresh("old", user_id);
    store
        .issue_oauth_tokens(
            &test_id,
            &test_id,
            OAuthTokenIssuance {
                access_token: None,
                refresh_token: Some(original),
            },
        )
        .await
        .unwrap();
    let original = store
        .find_oauth_refresh_token("old")
        .await
        .unwrap()
        .unwrap();
    let rotation = OAuthRefreshRotation {
        previous_refresh_id: original.id,
        rotated_at: Utc::now(),
        replay_expires_at: None,
        next_refresh_token: refresh("new", user_id),
        access_token: None,
    };
    let rotated = store
        .rotate_oauth_refresh_token(&test_id, &test_id, rotation.clone())
        .await
        .unwrap();
    let OAuthRefreshRotationOutcome::Rotated(next) = rotated else {
        panic!("expected rotation")
    };
    assert!(matches!(
        store
            .rotate_oauth_refresh_token(&test_id, &test_id, rotation)
            .await
            .unwrap(),
        OAuthRefreshRotationOutcome::AlreadyConsumed(_)
    ));
    assert_eq!(
        store
            .find_oauth_refresh_token("new")
            .await
            .unwrap()
            .unwrap()
            .id,
        next.id
    );
}
