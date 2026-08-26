use super::database_create;
use chrono::Utc;
use lucid_auth::{
    AuthService, AuthStore, NewPasswordUser, StepUpAssurance, StepUpSession, StepUpStore,
    StoredPasskey, postgres::PostgresStore,
};

pub async fn assert_tables_absent(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    for table in [
        "lucid_auth_step_up_sessions",
        "lucid_auth_step_up_recovery_codes",
    ] {
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
                .bind(table)
                .fetch_one(pool)
                .await?,
            "core migration unexpectedly created {table}"
        );
    }
    Ok(())
}

pub async fn assert_atomic(
    service: &AuthService,
    store: &PostgresStore,
    _pool: &sqlx::PgPool,
    signed_in: &lucid_auth::SignInResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = store
        .find_step_up_session(&signed_in.session.session.id)
        .await?
        .unwrap();
    assert_eq!(state.assurance, StepUpAssurance::PendingPasskey);
    store
        .upsert_step_up_session(StepUpSession {
            assurance: StepUpAssurance::StrongPasskey,
            authenticated_at: Utc::now(),
            ..state
        })
        .await?;
    let recovery = service.step_up_policy().unwrap();
    let codes = recovery
        .generate_recovery_codes(&signed_in.session, "step-up password".into())
        .await?;
    let pending = service
        .sign_in_username("step_up_user", "step-up password".into(), None, None)
        .await?;
    let (left, right) = tokio::join!(
        recovery.verify_recovery_code(&pending.session, &codes[0], None, None),
        recovery.verify_recovery_code(&pending.session, &codes[0], None, None),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    Ok(())
}

pub async fn authenticate_fixture(
    service: &AuthService,
    store: &PostgresStore,
) -> Result<lucid_auth::SignInResult, Box<dyn std::error::Error>> {
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "step_up_user".into(),
            name: "Step Up User".into(),
            email: None,
            password: "step-up password".into(),
            role: "step-up-test".into(),
        })
        .await?;
    let now = Utc::now();
    store
        .save_passkey(database_create(
            StoredPasskey {
                id: String::new(),
                user_id: user.id.clone(),
                name: Some("Step-up key".into()),
                credential_id: format!("step-up-credential-{}", user.id),
                public_key: "public-key".into(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: None,
                aaguid: None,
                created_at: now,
            },
            "passkey",
        ))
        .await?;
    Ok(service
        .sign_in_username("step_up_user", "step-up password".into(), None, None)
        .await?)
}
