use axum::{body::Body, http::Request};
use chrono::Utc;
use lucid_auth::{
    AdminPlugin, AuthConfig, AuthError, AuthService, AuthStore, MemoryStepUpStore, MemoryStore,
    MemoryTwoFactorStore, NewPasswordUser, OperatorSecurityConfig, OperatorSecurityError,
    OperatorSecurityPlugin, OwnerPolicyPlugin, StepUpPolicyPlugin, StepUpStore, StoredPasskey,
    TwoFactorConfig, TwoFactorPlugin, TwoFactorRecord, TwoFactorStore,
};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct Fixture {
    service: Arc<AuthService>,
    auth_store: Arc<MemoryStore>,
}

fn service(configure: impl FnOnce(&mut AuthConfig, &Arc<MemoryStore>)) -> Fixture {
    let auth_store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([73_u8; 32]).unwrap();
    config
        .add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))
        .unwrap();
    config.add_plugin(OwnerPolicyPlugin).unwrap();
    config
        .add_plugin(OperatorSecurityPlugin::new(
            auth_store.clone(),
            OperatorSecurityConfig::default(),
        ))
        .unwrap();
    configure(&mut config, &auth_store);
    Fixture {
        service: Arc::new(AuthService::new(auth_store.clone(), config)),
        auth_store,
    }
}

async fn provision(service: &AuthService, username: &str, role: &str) -> lucid_auth::AuthUser {
    service
        .provision_password_user(NewPasswordUser {
            username: username.into(),
            name: username.into(),
            email: None,
            password: "initial-password".into(),
            role: role.into(),
        })
        .await
        .unwrap()
}

async fn create_managed_member(
    service: &AuthService,
) -> (
    lucid_auth::SignInResult,
    lucid_auth::AuthUser,
    lucid_auth::SignInResult,
) {
    provision(service, "owner", "owner").await;
    let owner = service
        .sign_in_username("owner", "initial-password".into(), None, None)
        .await
        .unwrap();
    let member = service
        .create_user(
            &owner.session,
            NewPasswordUser {
                username: "member".into(),
                name: "Member".into(),
                email: None,
                password: "temporary-password".into(),
                role: "member".into(),
            },
        )
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username("member", "temporary-password".into(), None, None)
        .await
        .unwrap();
    (owner, member, signed_in)
}

async fn assert_temporary_access_is_restricted(
    service: &AuthService,
    member: &lucid_auth::AuthUser,
    signed_in: &lucid_auth::SignInResult,
) {
    assert!(service.session(&signed_in.token).await.unwrap().is_some());
    assert!(matches!(
        service.principal(&signed_in.token).await,
        Err(AuthError::OperatorSecurity(
            OperatorSecurityError::TemporaryPasswordRequired
        ))
    ));
    assert!(
        service
            .operator_security()
            .unwrap()
            .status(member.id)
            .await
            .unwrap()
            .temporary_password
    );
}

async fn replace_password_and_assert_access(
    service: &AuthService,
    member: &lucid_auth::AuthUser,
    signed_in: &lucid_auth::SignInResult,
) {
    service
        .change_password(
            &signed_in.session,
            "temporary-password".into(),
            "private-password".into(),
            true,
            None,
            None,
        )
        .await
        .unwrap();
    let replacement = service
        .sign_in_username("member", "private-password".into(), None, None)
        .await
        .unwrap();
    assert!(
        service
            .principal(&replacement.token)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        !service
            .operator_security()
            .unwrap()
            .status(member.id)
            .await
            .unwrap()
            .temporary_password
    );
}

#[tokio::test]
async fn administrator_passwords_require_replacement_only_with_the_plugin() {
    let fixture = service(|_, _| {});
    let (owner, member, signed_in) = create_managed_member(&fixture.service).await;
    assert_temporary_access_is_restricted(&fixture.service, &member, &signed_in).await;
    replace_password_and_assert_access(&fixture.service, &member, &signed_in).await;
    fixture
        .service
        .set_user_password(&owner.session, member.id, "reset-password".into())
        .await
        .unwrap();
    assert!(
        fixture
            .service
            .operator_security()
            .unwrap()
            .status(member.id)
            .await
            .unwrap()
            .temporary_password
    );
}

struct RecoveryFixture {
    fixture: Fixture,
    factors: Arc<MemoryTwoFactorStore>,
    step_up: Arc<MemoryStepUpStore>,
    owner: lucid_auth::AuthUser,
    signed_in: lucid_auth::SignInResult,
}

async fn recovery_fixture() -> RecoveryFixture {
    let factors = Arc::new(MemoryTwoFactorStore::default());
    let step_up = Arc::new(MemoryStepUpStore::default());
    let fixture = service(|config, auth_store| {
        config
            .add_plugin(TwoFactorPlugin::new(
                factors.clone(),
                TwoFactorConfig::default(),
            ))
            .unwrap();
        config
            .add_plugin(StepUpPolicyPlugin::new(
                auth_store.clone(),
                step_up.clone(),
                OwnerPolicyPlugin::step_up_config(),
            ))
            .unwrap();
    });
    let owner = provision(&fixture.service, "owner", "owner").await;
    let signed_in = fixture
        .service
        .sign_in_username("owner", "initial-password".into(), None, None)
        .await
        .unwrap();
    seed_recovery_state(&fixture, &factors, &owner).await;
    assert!(
        step_up
            .find_step_up_session(signed_in.session.session.id)
            .await
            .unwrap()
            .is_some()
    );
    RecoveryFixture {
        fixture,
        factors,
        step_up,
        owner,
        signed_in,
    }
}

async fn seed_recovery_state(
    fixture: &Fixture,
    factors: &MemoryTwoFactorStore,
    owner: &lucid_auth::AuthUser,
) {
    let now = Utc::now();
    fixture
        .auth_store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: owner.id,
            name: Some("Lost key".into()),
            credential_id: "lost-credential".into(),
            public_key: "public-key".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            aaguid: None,
            created_at: now,
        })
        .await
        .unwrap();
    factors
        .upsert_two_factor(TwoFactorRecord {
            id: Uuid::new_v4(),
            user_id: owner.id,
            encrypted_secret: "secret".into(),
            encrypted_backup_codes: "codes".into(),
            verified: true,
            failed_verification_count: 0,
            locked_until: None,
        })
        .await
        .unwrap();
    factors
        .set_two_factor_enabled(owner.id, true)
        .await
        .unwrap();
}

async fn assert_recovery_cleanup(recovery: &RecoveryFixture) {
    let service = &recovery.fixture.service;
    assert!(
        service
            .session(&recovery.signed_in.token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        service
            .list_passkeys(recovery.owner.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        recovery
            .factors
            .find_two_factor(recovery.owner.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        recovery
            .step_up
            .find_step_up_session(recovery.signed_in.session.session.id)
            .await
            .unwrap()
            .is_none()
    );
}

async fn assert_recovered_access_is_restricted(recovery: &RecoveryFixture) {
    let service = &recovery.fixture.service;
    let recovered = service
        .sign_in_username("owner", "recovered-password".into(), None, None)
        .await
        .unwrap();
    assert!(matches!(
        service.principal(&recovered.token).await,
        Err(AuthError::OperatorSecurity(
            OperatorSecurityError::TemporaryPasswordRequired
        ))
    ));
    assert!(matches!(
        service
            .list_users(
                &recovered.session,
                lucid_auth::AdminListUsersQuery {
                    limit: 10,
                    ..Default::default()
                },
            )
            .await,
        Err(AuthError::OperatorSecurity(
            OperatorSecurityError::TemporaryPasswordRequired
        ))
    ));
}

async fn assert_multiple_owner_recovery_is_refused(recovery: &RecoveryFixture) {
    let service = &recovery.fixture.service;
    provision(service, "second_owner", "owner").await;
    let error = service
        .operator_security()
        .unwrap()
        .local_recover_sole_owner("owner", "another-password".into())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthError::OperatorSecurity(OperatorSecurityError::SoleOwnerRecoveryUnavailable)
    ));
    assert!(
        service
            .sign_in_username("owner", "recovered-password".into(), None, None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn provisioned_password_policy_is_plugin_configuration() {
    let auth_store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([74_u8; 32]).unwrap();
    config
        .add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))
        .unwrap();
    config.add_plugin(OwnerPolicyPlugin).unwrap();
    config
        .add_plugin(OperatorSecurityPlugin::new(
            auth_store.clone(),
            OperatorSecurityConfig {
                provisioned_passwords_are_temporary: true,
                ..OperatorSecurityConfig::default()
            },
        ))
        .unwrap();
    let service = AuthService::new(auth_store, config);
    let user = provision(&service, "bootstrap", "owner").await;
    assert!(
        service
            .operator_security()
            .unwrap()
            .status(user.id)
            .await
            .unwrap()
            .temporary_password
    );
}

#[tokio::test]
async fn recovery_is_atomic_refuses_multiple_owners_and_cleans_enabled_factors() {
    let recovery = recovery_fixture().await;
    recovery
        .fixture
        .service
        .operator_security()
        .unwrap()
        .local_recover_sole_owner("owner", "recovered-password".into())
        .await
        .unwrap();
    assert_recovery_cleanup(&recovery).await;
    assert_recovered_access_is_restricted(&recovery).await;
    assert_multiple_owner_recovery_is_refused(&recovery).await;
}

#[tokio::test]
async fn operator_recovery_has_no_http_endpoint() {
    let fixture = service(|_, _| {});
    assert!(
        fixture
            .service
            .plugin_metadata()
            .iter()
            .find(|descriptor| descriptor.id == "lucid-operator-security")
            .unwrap()
            .endpoints
            .is_empty()
    );
    let response = lucid_auth::axum::router(fixture.service)
        .oneshot(
            Request::post("/api/auth/operator-security/recover")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}
