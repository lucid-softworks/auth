use chrono::{Duration, Utc};
use lucid_auth::{
    Assurance, AuthConfig, AuthService, AuthStore, MemoryStore, NewPasswordUser, Principal,
    StoredPasskey,
};
use std::sync::Arc;
use uuid::Uuid;

fn service(allow_anonymous: bool) -> AuthService {
    let mut config = AuthConfig::new([7_u8; 32]).unwrap();
    config.allow_anonymous = allow_anonymous;
    AuthService::new(Arc::new(MemoryStore::default()), config)
}

#[test]
fn strong_sessions_remain_fresh_for_one_day_by_default() {
    let mut principal = Principal {
        actor_id: Uuid::new_v4(),
        subject_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        role: "owner".into(),
        assurance: Assurance::Passkey,
        guest_grant_id: None,
        permissions: Vec::new(),
        resource_scopes: Vec::new(),
        must_change_password: false,
        authenticated_at: Utc::now() - Duration::hours(23),
        expires_at: Utc::now() + Duration::hours(1),
    };
    let mut config = AuthConfig::new([7_u8; 32]).unwrap();
    config.required_mfa_roles = vec!["owner".into()];
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);

    assert!(!service.step_up_required(&principal));
    principal.authenticated_at = Utc::now() - Duration::hours(25);
    assert!(service.step_up_required(&principal));
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
    assert_eq!(result.session.principal().assurance, Assurance::Password);
    assert!(service.session(&result.token).await.unwrap().is_some());
}

#[tokio::test]
async fn creates_a_restricted_anonymous_principal() {
    let service = service(true);
    let result = service.sign_in_anonymous(None, None).await.unwrap();

    assert!(result.session.user.is_anonymous);
    assert_eq!(result.session.user.role, "guest");
    assert_eq!(result.session.principal().assurance, Assurance::Anonymous);
}

#[tokio::test]
async fn enrolled_accounts_require_passkey_completion_after_password() {
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
    let now = Utc::now();
    store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: user.id,
            name: Some("Test passkey".into()),
            credential_id: "test-credential".into(),
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
        result.session.session.assurance,
        Assurance::PasswordPendingPasskey
    );
    assert!(!result.mfa_setup_required);
}

#[tokio::test]
async fn configured_roles_must_enroll_a_passkey_after_password() {
    let mut config = AuthConfig::new([17_u8; 32]).unwrap();
    config.required_mfa_roles = vec!["owner".into()];
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
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

    let result = service
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap();
    assert_eq!(
        result.session.session.assurance,
        Assurance::PasswordPendingPasskey
    );
    assert!(result.mfa_setup_required);
}

#[tokio::test]
async fn enabling_required_mfa_invalidates_existing_password_only_sessions() {
    let store = Arc::new(MemoryStore::default());
    let initial = AuthService::new(store.clone(), AuthConfig::new([21_u8; 32]).unwrap());
    initial
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let signed_in = initial
        .sign_in_username("luna", "password".into(), None, None)
        .await
        .unwrap();

    let mut hardened_config = AuthConfig::new([21_u8; 32]).unwrap();
    hardened_config.required_mfa_roles = vec!["owner".into()];
    let hardened = AuthService::new(store, hardened_config);

    assert!(hardened.session(&signed_in.token).await.unwrap().is_none());
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
