use chrono::{Duration, Utc};
use lucid_auth::{
    AdminPlugin, AuthConfig, AuthError, AuthService, AuthStore, AuthenticationMethod,
    MemoryStepUpStore, MemoryStore, NewPasswordUser, OwnerPolicyPlugin, PasskeyConfig,
    PasskeyPlugin, StepUpAssurance, StepUpPolicyConfig, StepUpPolicyPlugin, StepUpSession,
    StepUpStore, StoredPasskey, TwoFactorConfig, TwoFactorPlugin,
};
use std::sync::Arc;
use uuid::Uuid;

struct Fixture {
    service: AuthService,
    auth_store: Arc<MemoryStore>,
    step_up_store: Arc<MemoryStepUpStore>,
    owner: lucid_auth::SignInResult,
    member: lucid_auth::AuthUser,
}

async fn fixture(freshness: Duration) -> Fixture {
    let auth_store = Arc::new(MemoryStore::default());
    let step_up_store = Arc::new(MemoryStepUpStore::default());
    let mut config = AuthConfig::new([72_u8; 32]).unwrap();
    config
        .add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))
        .unwrap();
    config.add_plugin(OwnerPolicyPlugin).unwrap();
    config
        .add_plugin(StepUpPolicyPlugin::new(
            auth_store.clone(),
            step_up_store.clone(),
            StepUpPolicyConfig {
                freshness,
                ..OwnerPolicyPlugin::step_up_config()
            },
        ))
        .unwrap();
    let service = AuthService::new(auth_store.clone(), config);
    service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Owner".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let member = service
        .provision_password_user(NewPasswordUser {
            username: "member".into(),
            name: "Member".into(),
            email: None,
            password: "password".into(),
            role: "member".into(),
        })
        .await
        .unwrap();
    let owner = service
        .sign_in_username("owner", "password".into(), None, None)
        .await
        .unwrap();
    Fixture {
        service,
        auth_store,
        step_up_store,
        owner,
        member,
    }
}

#[tokio::test]
async fn core_password_sessions_have_no_step_up_policy_when_the_plugin_is_disabled() {
    let service = AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([73_u8; 32]).unwrap(),
    );
    service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Owner".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username("owner", "password".into(), None, None)
        .await
        .unwrap();

    assert_eq!(
        signed_in.session.session.authentication_method,
        Some(AuthenticationMethod::Password)
    );
    assert!(service.step_up_policy().is_none());
    assert!(service.session(&signed_in.token).await.unwrap().is_some());
}

#[tokio::test]
async fn policy_tracks_enrollment_and_blocks_sensitive_operations_until_step_up() {
    let fixture = fixture(Duration::days(1)).await;
    let state = fixture
        .step_up_store
        .find_step_up_session(fixture.owner.session.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.assurance, StepUpAssurance::PendingEnrollment);
    let projection = fixture
        .service
        .step_up_policy()
        .unwrap()
        .session_projection(&fixture.owner.session)
        .await
        .unwrap();
    assert!(projection.required);
    assert!(projection.step_up_required);
    assert!(!projection.fresh);
    assert_eq!(
        projection.assurance,
        Some(StepUpAssurance::PendingEnrollment)
    );
    assert!(matches!(
        fixture
            .service
            .set_user_role(&fixture.owner.session, fixture.member.id, "viewer")
            .await,
        Err(AuthError::StepUpRequired)
    ));

    fixture
        .step_up_store
        .upsert_step_up_session(StepUpSession {
            assurance: StepUpAssurance::StrongPasskey,
            authenticated_at: Utc::now(),
            ..state
        })
        .await
        .unwrap();
    fixture
        .service
        .set_user_role(&fixture.owner.session, fixture.member.id, "viewer")
        .await
        .unwrap();
}

#[tokio::test]
async fn stale_step_up_state_is_rejected() {
    let fixture = fixture(Duration::hours(1)).await;
    fixture
        .step_up_store
        .upsert_step_up_session(StepUpSession {
            session_id: fixture.owner.session.session.id,
            user_id: fixture.owner.session.user.id,
            assurance: StepUpAssurance::StrongTwoFactor,
            authenticated_at: Utc::now() - Duration::hours(2),
        })
        .await
        .unwrap();

    assert!(matches!(
        fixture
            .service
            .set_user_role(&fixture.owner.session, fixture.member.id, "viewer")
            .await,
        Err(AuthError::StepUpRequired)
    ));
}

#[tokio::test]
async fn enabling_policy_invalidates_untracked_existing_required_role_sessions() {
    let auth_store = Arc::new(MemoryStore::default());
    let initial = AuthService::new(auth_store.clone(), AuthConfig::new([74_u8; 32]).unwrap());
    initial
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Owner".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let existing = initial
        .sign_in_username("owner", "password".into(), None, None)
        .await
        .unwrap();

    let mut config = AuthConfig::new([74_u8; 32]).unwrap();
    config
        .add_plugin(StepUpPolicyPlugin::new(
            auth_store.clone(),
            Arc::new(MemoryStepUpStore::default()),
            OwnerPolicyPlugin::step_up_config(),
        ))
        .unwrap();
    let hardened = AuthService::new(auth_store, config);

    assert!(hardened.session(&existing.token).await.unwrap().is_none());
}

#[tokio::test]
async fn passkey_enrollment_produces_pending_state_and_recovery_codes_are_one_time() {
    let fixture = fixture(Duration::days(1)).await;
    let now = Utc::now();
    fixture
        .auth_store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: fixture.owner.session.user.id,
            name: Some("Passkey".into()),
            credential_id: "credential".into(),
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
    fixture
        .step_up_store
        .upsert_step_up_session(StepUpSession {
            session_id: fixture.owner.session.session.id,
            user_id: fixture.owner.session.user.id,
            assurance: StepUpAssurance::StrongPasskey,
            authenticated_at: now,
        })
        .await
        .unwrap();
    let plugin = fixture.service.step_up_policy().unwrap();
    let codes = plugin
        .generate_recovery_codes(&fixture.owner.session, "password".into())
        .await
        .unwrap();
    assert_eq!(codes.len(), 10);

    let pending = fixture
        .service
        .sign_in_username("owner", "password".into(), None, None)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .step_up_store
            .find_step_up_session(pending.session.session.id)
            .await
            .unwrap()
            .unwrap()
            .assurance,
        StepUpAssurance::PendingPasskey
    );
    let (left, right) = tokio::join!(
        plugin.verify_recovery_code(&pending.session, &codes[0], None, None),
        plugin.verify_recovery_code(&pending.session, &codes[0], None, None),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let recovered = left.or(right).unwrap();
    assert_eq!(
        fixture
            .step_up_store
            .find_step_up_session(recovered.session.session.id)
            .await
            .unwrap()
            .unwrap()
            .assurance,
        StepUpAssurance::Recovery
    );
    assert_eq!(
        plugin
            .recovery_code_status(&recovered.session)
            .await
            .unwrap()
            .remaining,
        9
    );
}

#[test]
fn step_up_composes_with_official_passkey_and_two_factor_plugins() {
    let auth_store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([75_u8; 32]).unwrap();
    config
        .add_plugin(PasskeyPlugin::new(PasskeyConfig::default()))
        .unwrap();
    config
        .add_plugin(TwoFactorPlugin::new(
            Arc::new(lucid_auth::MemoryTwoFactorStore::default()),
            TwoFactorConfig::default(),
        ))
        .unwrap();
    config
        .add_plugin(StepUpPolicyPlugin::new(
            auth_store.clone(),
            Arc::new(MemoryStepUpStore::default()),
            OwnerPolicyPlugin::step_up_config(),
        ))
        .unwrap();
    let service = AuthService::try_new(auth_store, config).unwrap();
    let ids: Vec<_> = service
        .plugin_metadata()
        .iter()
        .map(|descriptor| descriptor.id)
        .collect();

    assert!(ids.contains(&"passkey"));
    assert!(ids.contains(&"two-factor"));
    assert!(ids.contains(&"lucid-step-up-policy"));
}
