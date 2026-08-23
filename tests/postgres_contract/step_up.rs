use chrono::Utc;
use lucid_auth::{
    AuthService, AuthStore, NewPasswordUser, StepUpAssurance, StepUpSession, StepUpStore,
    StoredPasskey, postgres::PostgresStore,
};
use serde_json::json;
use uuid::Uuid;

pub struct LegacyStepUp {
    session_id: Uuid,
    user_id: Uuid,
    code_hash: String,
}

pub async fn assert_tables_absent(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    for table in [
        "lucid_auth_step_up_sessions",
        "lucid_auth_step_up_recovery_codes",
        "lucid_auth_recovery_codes",
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

pub async fn insert_legacy_shape(
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<LegacyStepUp, Box<dyn std::error::Error>> {
    let session_id = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO lucid_auth_sessions \
         (id, user_id, token_hash, actor_user_id, authentication_method, expires_at, created_at, \
          updated_at, ip_address, user_agent) \
         VALUES ($1,$2,$3,NULL,'passkey',$4,$5,$5,NULL,NULL)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(format!("legacy-step-up-{session_id}"))
    .bind(now + chrono::Duration::hours(1))
    .bind(now)
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE lucid_auth_legacy_session_assurance (\
           session_id UUID PRIMARY KEY REFERENCES lucid_auth_sessions(id) ON DELETE CASCADE,\
           user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,\
           assurance TEXT NOT NULL,\
           authenticated_at TIMESTAMPTZ NOT NULL\
         )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO lucid_auth_legacy_session_assurance \
         (session_id, user_id, assurance, authenticated_at) \
         VALUES ($1,$2,'password_and_passkey',$3)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(now)
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE lucid_auth_recovery_codes (\
           user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,\
           code_hash TEXT NOT NULL,\
           created_at TIMESTAMPTZ NOT NULL,\
           PRIMARY KEY (user_id, code_hash)\
         )",
    )
    .execute(pool)
    .await?;
    let code_hash = "legacy-recovery-code".to_owned();
    sqlx::query(
        "INSERT INTO lucid_auth_recovery_codes (user_id, code_hash, created_at) \
         VALUES ($1,$2,$3)",
    )
    .bind(user_id)
    .bind(&code_hash)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(LegacyStepUp {
        session_id,
        user_id,
        code_hash,
    })
}

pub async fn assert_legacy_migrated(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    legacy: LegacyStepUp,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        store
            .find_step_up_session(legacy.session_id)
            .await?
            .unwrap()
            .assurance,
        StepUpAssurance::StrongPasskey
    );
    assert_eq!(store.step_up_recovery_code_count(legacy.user_id).await?, 1);
    assert!(
        store
            .consume_step_up_recovery_code(legacy.user_id, &legacy.code_hash)
            .await?
    );
    for legacy_table in [
        "lucid_auth_legacy_session_assurance",
        "lucid_auth_recovery_codes",
    ] {
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
                .bind(legacy_table)
                .fetch_one(pool)
                .await?
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
        .find_step_up_session(signed_in.session.session.id)
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
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: user.id,
            name: Some("Step-up key".into()),
            credential_id: format!("step-up-credential-{}", user.id),
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
        .await?;
    Ok(service
        .sign_in_username("step_up_user", "step-up password".into(), None, None)
        .await?)
}
