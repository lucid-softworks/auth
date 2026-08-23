use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, MemoryStore, NewPasswordUser, PasswordBreachChecker,
};
use std::sync::Arc;

struct Compromised;

#[async_trait]
impl PasswordBreachChecker for Compromised {
    async fn is_compromised(&self, _: &str) -> Result<bool, AuthError> {
        Ok(true)
    }
}

#[tokio::test]
async fn rejects_a_compromised_password_before_hashing() {
    let mut config = AuthConfig::new([51_u8; 32]).unwrap();
    config.password_breach_checker = Some(Arc::new(Compromised));
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    let error = service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "compromised-password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::PasswordCompromised));
}

#[tokio::test]
async fn reprovisioning_preserves_an_account_owned_password() {
    let service = AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([31_u8; 32]).unwrap(),
    );
    for password in ["original-password", "configured-replacement"] {
        service
            .provision_password_user(NewPasswordUser {
                username: "luna".into(),
                name: "Luna".into(),
                email: None,
                password: password.into(),
                role: "owner".into(),
            })
            .await
            .unwrap();
    }

    assert!(
        service
            .sign_in_username("luna", "original-password".into(), None, None)
            .await
            .is_ok()
    );
    assert!(
        service
            .sign_in_username("luna", "configured-replacement".into(), None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn changes_a_password_and_rotates_other_sessions() {
    let service = AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([41_u8; 32]).unwrap(),
    );
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "old-password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let current = service
        .sign_in_username("luna", "old-password".into(), None, None)
        .await
        .unwrap();
    let other = service
        .sign_in_username("luna", "old-password".into(), None, None)
        .await
        .unwrap();

    let changed = service
        .change_password(
            &current.session,
            "old-password".into(),
            "new-password".into(),
            true,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(service.session(&current.token).await.unwrap().is_none());
    assert!(service.session(&other.token).await.unwrap().is_none());
    assert!(
        service
            .session(&changed.replacement_session.unwrap().token)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        service
            .sign_in_username("luna", "old-password".into(), None, None)
            .await
            .is_err()
    );
    assert!(
        service
            .sign_in_username("luna", "new-password".into(), None, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn account_throttling_survives_service_recreation() {
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([61_u8; 32]).unwrap();
    config.max_attempts = 3;
    let service = AuthService::new(store.clone(), config.clone());
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "correct-password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    for _ in 0..3 {
        assert!(matches!(
            service
                .sign_in_username("luna", "wrong-password".into(), None, None)
                .await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    let restarted = AuthService::new(store, config);
    assert!(matches!(
        restarted
            .sign_in_username("luna", "correct-password".into(), None, None)
            .await,
        Err(AuthError::RateLimited)
    ));
}

#[tokio::test]
async fn ip_throttling_spans_multiple_account_names() {
    let mut config = AuthConfig::new([71_u8; 32]).unwrap();
    config.max_ip_attempts = 3;
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "correct-password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    for username in ["first", "second", "third"] {
        assert!(matches!(
            service
                .sign_in_username(
                    username,
                    "wrong-password".into(),
                    Some("192.0.2.4".into()),
                    None,
                )
                .await,
            Err(AuthError::InvalidCredentials)
        ));
    }
    assert!(matches!(
        service
            .sign_in_username(
                "luna",
                "correct-password".into(),
                Some("192.0.2.4".into()),
                None,
            )
            .await,
        Err(AuthError::RateLimited)
    ));
}
