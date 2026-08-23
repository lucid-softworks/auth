use super::*;
use crate::{
    AuthConfig, AuthStore, MemoryStore, NewPasswordUser, PasskeyConfig, PasskeyRegistrationUser,
    PasskeyRegistrationUserResolver,
};
use chrono::{DateTime, Duration};
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
    let session = service
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap()
        .session;
    let now = Utc::now();
    let passkey = store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: session.user.id,
            name: Some("Original".into()),
            credential_id: "credential".into(),
            public_key: "public-key".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            aaguid: None,
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
    service.delete_passkey(&session, passkey.id).await.unwrap();
    assert!(
        service
            .list_passkeys(session.user.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn better_auth_deletion_does_not_apply_native_role_policy() {
    let store = Arc::new(MemoryStore::default());
    let service = AuthService::new(store.clone(), AuthConfig::new([48_u8; 32]).unwrap());
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
    let session = service
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap()
        .session;
    let now = Utc::now();
    let first = test_passkey(session.user.id, "first", now);
    let second = test_passkey(session.user.id, "second", now);
    store.save_passkey(first.clone()).await.unwrap();
    store.save_passkey(second.clone()).await.unwrap();
    let (left, right) = tokio::join!(
        service.delete_passkey(&session, first.id),
        service.delete_passkey(&session, second.id)
    );
    assert!(left.is_ok());
    assert!(right.is_ok());
    assert_eq!(
        service.list_passkeys(session.user.id).await.unwrap().len(),
        0
    );
}

#[tokio::test]
async fn passkey_ceremonies_cross_service_instances_and_consume_once() {
    let store = Arc::new(MemoryStore::default());
    let config = AuthConfig::new([49_u8; 32]).unwrap();
    let passkeys = PasskeyConfig {
        rp_id: Some("localhost".into()),
        rp_name: Some("Local".into()),
        origins: Some(vec!["http://localhost:5173".into()]),
        ..PasskeyConfig::default()
    };
    let first = AuthService::new(store.clone(), config.clone());
    let second = AuthService::new(store, config);
    first
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let session = first
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap()
        .session;
    let (token, _) = first
        .start_passkey_registration(
            &passkeys,
            Some(&session),
            PasskeyRegistrationRequest {
                name: None,
                context: None,
                authenticator_attachment: None,
            },
        )
        .await
        .unwrap();

    let ceremony = second
        .consume_passkey_ceremony(REGISTRATION_PURPOSE, &token)
        .await
        .unwrap();
    assert!(matches!(
        ceremony,
        PasskeyCeremony::Registration { user_id, .. } if user_id == session.user.id
    ));
    assert!(matches!(
        first
            .consume_passkey_ceremony(REGISTRATION_PURPOSE, &token)
            .await,
        Err(AuthError::PasskeyChallengeExpired)
    ));
}

#[tokio::test]
async fn registration_requires_a_fresh_session() {
    let store = Arc::new(MemoryStore::default());
    let service = AuthService::new(store, AuthConfig::new([50_u8; 32]).unwrap());
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
    session.session.created_at = Utc::now() - Duration::days(2);
    let error = service
        .start_passkey_registration(
            &PasskeyConfig::default(),
            Some(&session),
            PasskeyRegistrationRequest {
                name: None,
                context: None,
                authenticator_attachment: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::SessionNotFresh));
}

#[tokio::test]
async fn passkey_counter_updates_compare_and_swap() {
    let store = MemoryStore::default();
    let now = Utc::now();
    let passkey = test_passkey(Uuid::new_v4(), "counter", now);
    store.save_passkey(passkey.clone()).await.unwrap();
    let mut left = passkey.clone();
    left.counter = 1;
    let mut right = passkey;
    right.counter = 2;
    let (left, right) = tokio::join!(
        store.update_passkey_after_authentication(left, 0),
        store.update_passkey_after_authentication(right, 0),
    );
    assert_eq!(usize::from(left.unwrap()) + usize::from(right.unwrap()), 1);
}

struct RegistrationResolver(PasskeyRegistrationUser);

#[async_trait::async_trait]
impl PasskeyRegistrationUserResolver for RegistrationResolver {
    async fn resolve(&self, context: Option<&str>) -> Result<PasskeyRegistrationUser, AuthError> {
        assert_eq!(context, Some("invite-42"));
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn passkey_first_registration_resolves_the_context_user_without_a_session() {
    let store = Arc::new(MemoryStore::default());
    let service = AuthService::new(store, AuthConfig::new([51_u8; 32]).unwrap());
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let mut config = PasskeyConfig::default();
    config.registration.require_session = false;
    config.registration.resolve_user =
        Some(Arc::new(RegistrationResolver(PasskeyRegistrationUser {
            id: user.id,
            name: "resolved@example.com".into(),
            display_name: Some("Resolved User".into()),
        })));
    let (token, options) = service
        .start_passkey_registration(
            &config,
            None,
            PasskeyRegistrationRequest {
                name: None,
                context: Some("invite-42".into()),
                authenticator_attachment: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(options.public_key.user.name, "resolved@example.com");
    assert_eq!(options.public_key.user.display_name, "Resolved User");
    assert!(matches!(
        service
            .consume_passkey_ceremony(REGISTRATION_PURPOSE, &token)
            .await
            .unwrap(),
        PasskeyCeremony::Registration {
            user_id,
            context: Some(context),
            ..
        } if user_id == user.id && context == "invite-42"
    ));
}

fn test_passkey(user_id: Uuid, credential_id: &str, now: DateTime<Utc>) -> StoredPasskey {
    StoredPasskey {
        id: Uuid::new_v4(),
        user_id,
        name: Some(credential_id.into()),
        credential_id: credential_id.into(),
        public_key: "public-key".into(),
        counter: 0,
        device_type: "singleDevice".into(),
        backed_up: false,
        transports: None,
        aaguid: None,
        credential: json!({}),
        created_at: now,
        updated_at: now,
    }
}
