use super::*;
use crate::{AuthConfig, AuthStore, MemoryStore, NewPasswordUser, SecurityStore};
use std::sync::Arc;

#[tokio::test]
async fn an_account_can_rename_and_delete_its_own_passkey() {
    let store = Arc::new(MemoryStore::default());
    let service = AuthService::new(store.clone(), AuthConfig::new([47_u8; 32]).unwrap());
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let mut session = service
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap()
        .session;
    session.session.assurance = Assurance::PasswordAndPasskey;
    let now = Utc::now();
    let passkey = store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: session.user.id,
            name: Some("Original".into()),
            credential_id: "credential".into(),
            credential: json!({}),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    let renamed = service
        .rename_passkey(&session, passkey.id, " Security key ")
        .await
        .unwrap();
    assert_eq!(renamed.name.as_deref(), Some("Security key"));
    store
        .replace_recovery_codes(session.user.id, vec!["stale-code".into()])
        .await
        .unwrap();
    service.delete_passkey(&session, passkey.id).await.unwrap();
    assert!(
        service
            .list_passkeys(session.user.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.recovery_code_count(session.user.id).await.unwrap(), 0);
}

#[tokio::test]
async fn required_mfa_preserves_one_passkey_under_concurrent_deletion() {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([48_u8; 32]).unwrap();
    config.required_mfa_roles = vec!["owner".into()];
    let service = AuthService::new(store.clone(), config);
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let mut session = service
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap()
        .session;
    session.session.assurance = Assurance::PasswordAndPasskey;
    let now = Utc::now();
    let first = test_passkey(session.user.id, "first", now);
    let second = test_passkey(session.user.id, "second", now);
    store.save_passkey(first.clone()).await.unwrap();
    store.save_passkey(second.clone()).await.unwrap();
    let (left, right) = tokio::join!(
        service.delete_passkey(&session, first.id),
        service.delete_passkey(&session, second.id)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(AuthError::LastPasskey)) || matches!(right, Err(AuthError::LastPasskey))
    );
    assert_eq!(
        service.list_passkeys(session.user.id).await.unwrap().len(),
        1
    );
}

fn test_passkey(user_id: Uuid, credential_id: &str, now: DateTime<Utc>) -> StoredPasskey {
    StoredPasskey {
        id: Uuid::new_v4(),
        user_id,
        name: Some(credential_id.into()),
        credential_id: credential_id.into(),
        credential: json!({}),
        created_at: now,
        updated_at: now,
    }
}
