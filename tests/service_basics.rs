use lucid_auth::{
    AuthConfig, AuthService, AuthStore, AuthenticationMethod, MemoryStore, NewPasswordUser,
    StoredPasskey,
};
use std::sync::Arc;
use uuid::Uuid;

fn service(allow_anonymous: bool) -> AuthService {
    let mut config = AuthConfig::new([7_u8; 32]).unwrap();
    config.allow_anonymous = allow_anonymous;
    AuthService::new(Arc::new(MemoryStore::default()), config)
}

#[tokio::test]
async fn provisions_and_authenticates_a_password_user() {
    let service = service(false);
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "Luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();

    let result = service
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap();

    assert_eq!(result.session.user, user);
    assert_eq!(result.session.principal().actor_id, user.id);
    assert_eq!(
        result.session.principal().authentication_method,
        AuthenticationMethod::Password
    );
    assert!(service.session(&result.token).await.unwrap().is_some());
}

#[tokio::test]
async fn creates_a_restricted_anonymous_principal() {
    let service = service(true);
    let result = service.sign_in_anonymous(None, None).await.unwrap();

    assert!(result.session.user.is_anonymous);
    assert_eq!(result.session.user.role, "guest");
    assert_eq!(
        result.session.principal().authentication_method,
        AuthenticationMethod::Anonymous
    );
}

#[tokio::test]
async fn enrolled_accounts_still_receive_a_normal_password_session() {
    let store = Arc::new(MemoryStore::default());
    let service = AuthService::new(store.clone(), AuthConfig::new([7_u8; 32]).unwrap());
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
    let now = chrono::Utc::now();
    store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: user.id,
            name: Some("Test passkey".into()),
            credential_id: "test-credential".into(),
            public_key: "public-key".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            aaguid: None,
            credential: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();

    let result = service
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap();

    assert_eq!(
        result.session.session.authentication_method,
        AuthenticationMethod::Password
    );
}

#[test]
fn rejects_modified_session_cookies() {
    let service = service(false);
    let signed = service.signed_cookie_value("session-token");
    assert_eq!(
        service.verify_cookie_value(&signed).as_deref(),
        Some("session-token")
    );
    assert!(
        service
            .verify_cookie_value(&format!("changed{signed}"))
            .is_none()
    );
}
