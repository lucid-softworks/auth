use chrono::{Duration, Utc};
use lucid_auth::{
    Assurance, AuthConfig, AuthError, AuthService, AuthSession, AuthStore, AuthUser,
    EmailSignUpInput, EmailVerificationOutcome, NewPasswordUser, PasskeyConfig, PasskeyPlugin,
    PasswordResetOutcome, PluginMigration, PluginMigrationContribution, UsernameError,
    UsernamePlugin, VerificationStore, VerificationValue, postgres::PostgresStore,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

#[path = "postgres_contract/api_key.rs"]
mod api_key;
#[path = "postgres_contract/passkey.rs"]
mod passkey;

use passkey::{
    assert_legacy_passkey_migrated, insert_legacy_passkey, passkey_counters_are_atomic,
    passkey_public_key_column_count,
};

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn migrations_and_authentication_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let schema = format!("lucid_auth_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await?;

    let search_path = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _metadata| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(&search_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await?;

    let store = Arc::new(PostgresStore::new(pool.clone()));
    store.migrate().await?;
    store.migrate().await?;
    plugin_migrations_are_idempotent(&store, &pool).await?;
    assert_eq!(passkey_public_key_column_count(&pool).await?, 0);
    api_key::assert_table_absent(&pool).await?;

    let mut config = AuthConfig::new([42_u8; 32])?;
    config.email_and_password.enabled = true;
    config.add_plugin(UsernamePlugin::default())?;
    config.add_plugin(PasskeyPlugin::new(PasskeyConfig::default()))?;
    let api_keys = api_key::register(&mut config)?;
    let service = Arc::new(AuthService::new(store.clone(), config));
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Example Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await?;
    let legacy = insert_legacy_passkey(&pool, user.id).await?;
    store.migrate_plugins(&service.plugin_migrations()).await?;
    store.migrate_plugins(&service.plugin_migrations()).await?;
    assert_eq!(passkey_public_key_column_count(&pool).await?, 1);
    assert_legacy_passkey_migrated(&store, &legacy).await?;
    let signed_in = service
        .sign_in_username(
            "owner",
            "correct horse battery staple".into(),
            Some("127.0.0.1".into()),
            Some("lucid-auth integration test".into()),
        )
        .await?;

    assert_eq!(signed_in.session.user, user);
    assert_eq!(signed_in.session.principal().subject_id, user.id);
    assert!(service.session(&signed_in.token).await?.is_some());

    verification_values_are_atomic(&store, user.id).await?;
    email_verification_is_atomic(&store, &user).await?;
    password_reset_is_atomic(&store, &pool, user.id).await?;
    magic_link_promotion_is_atomic(&store, &pool).await?;
    email_signup_is_case_insensitive(&service, &pool).await?;
    username_signup_is_atomic(&service, &pool).await?;
    passkey_counters_are_atomic(&store, user.id).await?;
    api_key::assert_limits_are_atomic(&service, &api_keys, &signed_in.session).await?;

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await?;
    admin.close().await;
    Ok(())
}

async fn magic_link_promotion_is_atomic(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let user = store
        .create_password_user(
            AuthUser {
                id: Uuid::new_v4(),
                username: None,
                display_username: None,
                name: "Unverified magic-link user".into(),
                email: "postgres-magic@example.com".into(),
                email_verified: false,
                image: None,
                role: "member".into(),
                is_anonymous: false,
                must_change_password: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            },
            "credential-hash".into(),
        )
        .await?;
    store
        .create_session(AuthSession {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: "unproven-magic-session".into(),
            actor_user_id: None,
            guest_grant_id: None,
            assurance: Assurance::Password,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
        })
        .await?;
    store
        .create_verification(VerificationValue {
            purpose: "magic-link".into(),
            identifier: "postgres-magic-token".into(),
            payload: json!({ "email": user.email }),
            expires_at: now + Duration::minutes(1),
            created_at: now,
        })
        .await?;
    let (left, right) = tokio::join!(
        store.consume_verification("magic-link", "postgres-magic-token", now),
        store.consume_verification("magic-link", "postgres-magic-token", now)
    );
    assert_eq!(
        usize::from(left?.is_some()) + usize::from(right?.is_some()),
        1
    );
    let promoted = store.promote_email_owner(user.id, now).await?.unwrap();
    assert!(promoted.email_verified);
    assert!(store.find_password_hash(user.id).await?.is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_sessions WHERE user_id = $1",
        )
        .bind(user.id)
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

async fn password_reset_is_atomic(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let token_hash = hex::encode(Sha256::digest(b"postgres-password-reset"));
    store
        .create_verification(VerificationValue {
            purpose: "password-reset".into(),
            identifier: token_hash.clone(),
            payload: json!({ "user_id": user_id }),
            expires_at: now + Duration::minutes(1),
            created_at: now,
        })
        .await?;
    let (left, right) = tokio::join!(
        store.consume_password_reset(&token_hash, "first-hash".into(), now, true),
        store.consume_password_reset(&token_hash, "second-hash".into(), now, true)
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PasswordResetOutcome::Reset(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PasswordResetOutcome::InvalidToken))
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_sessions WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

async fn email_verification_is_atomic(
    store: &PostgresStore,
    user: &lucid_auth::AuthUser,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let token_hash = hex::encode(Sha256::digest(b"postgres-email-verification"));
    store
        .create_verification(VerificationValue {
            purpose: "email-verification".into(),
            identifier: token_hash.clone(),
            payload: json!({ "email": user.email }),
            expires_at: now + Duration::minutes(1),
            created_at: now,
        })
        .await?;
    let (left, right) = tokio::join!(
        store.consume_email_verification(&token_hash, now),
        store.consume_email_verification(&token_hash, now)
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EmailVerificationOutcome::Verified(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EmailVerificationOutcome::InvalidToken))
            .count(),
        1
    );
    Ok(())
}

async fn plugin_migrations_are_idempotent(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_migrations = [PluginMigrationContribution {
        plugin_id: "postgres-contract",
        migration: PluginMigration {
            id: "create-records",
            description: "PostgreSQL contract plugin records",
            sql: "CREATE TABLE lucid_auth_contract_plugin_records (id TEXT PRIMARY KEY)",
        },
    }];
    store.migrate_plugins(&plugin_migrations).await?;
    store.migrate_plugins(&plugin_migrations).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_plugin_migrations \
             WHERE plugin_id = 'postgres-contract' AND migration_id = 'create-records'",
        )
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}

async fn email_signup_is_case_insensitive(
    service: &AuthService,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let signup = |email: &str| EmailSignUpInput {
        name: "PostgreSQL email user".into(),
        email: email.into(),
        password: "correct horse battery staple".into(),
        image: None,
        callback_url: None,
        remember_me: None,
        username: None,
        display_username: None,
    };
    let (left, right) = tokio::join!(
        service.sign_up_email(signup("Case.Variant@Example.com"), None, None),
        service.sign_up_email(signup("case.variant@example.com"), None, None)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let error = left.err().or_else(|| right.err()).unwrap();
    assert!(matches!(error, AuthError::UserAlreadyExistsEmail));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_users WHERE LOWER(email) = 'case.variant@example.com'",
        )
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}

async fn username_signup_is_atomic(
    service: &AuthService,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let signup = |email: &str, username: &str| EmailSignUpInput {
        name: "PostgreSQL username user".into(),
        email: email.into(),
        password: "correct horse battery staple".into(),
        image: None,
        callback_url: None,
        remember_me: None,
        username: Some(username.into()),
        display_username: None,
    };
    let (left, right) = tokio::join!(
        service.sign_up_email(
            signup("postgres-username-left@example.com", "Postgres_User"),
            None,
            None,
        ),
        service.sign_up_email(
            signup("postgres-username-right@example.com", "postgres_user"),
            None,
            None,
        )
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let error = left.err().or_else(|| right.err()).unwrap();
    assert!(matches!(
        error,
        AuthError::Username(UsernameError::AlreadyTaken)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_users WHERE username = 'postgres_user'",
        )
        .fetch_one(pool)
        .await?,
        1
    );
    Ok(())
}

async fn verification_values_are_atomic(
    store: &PostgresStore,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    store
        .create_verification(VerificationValue {
            purpose: "contract".into(),
            identifier: "single-use".into(),
            payload: json!({ "subject": user_id }),
            expires_at: now + Duration::minutes(1),
            created_at: now,
        })
        .await?;
    let (left, right) = tokio::join!(
        store.consume_verification("contract", "single-use", now),
        store.consume_verification("contract", "single-use", now)
    );
    assert_eq!(
        usize::from(left?.is_some()) + usize::from(right?.is_some()),
        1
    );

    store
        .create_verification(VerificationValue {
            purpose: "contract".into(),
            identifier: "expired".into(),
            payload: json!({}),
            expires_at: now - Duration::seconds(1),
            created_at: now - Duration::minutes(1),
        })
        .await?;
    assert!(
        store
            .consume_verification("contract", "expired", now)
            .await?
            .is_none()
    );
    Ok(())
}
