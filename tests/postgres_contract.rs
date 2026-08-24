use lucid_auth::{
    AccessStore, AccountDeleteOutcome, AdditionalField, AdditionalFieldType, AdminPlugin,
    AnonymousPlugin, AuditPlugin, AuthConfig, AuthError, AuthService, AuthStore, AuthUser,
    EmailSignUpInput, GuestCapabilityPlugin, NewPasswordUser, OAuthAccount, OAuthAccountStore,
    OAuthTokenUpdateOutcome, OperatorSecurityConfig, OperatorSecurityPlugin,
    OrganizationDynamicAccessControlConfig, OrganizationPlugin, OrganizationPluginConfig,
    OrganizationTeamsConfig, OwnerPolicyPlugin, PasskeyConfig, PasskeyPlugin, PluginMigration,
    PluginMigrationContribution, StepUpPolicyConfig, StepUpPolicyPlugin, TwoFactorConfig,
    TwoFactorPlugin, UsernameError, UsernamePlugin, postgres::PostgresStore,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

#[path = "postgres_contract/account_update.rs"]
mod account_update;
#[path = "postgres_contract/admin.rs"]
mod admin;
#[path = "postgres_contract/anonymous.rs"]
mod anonymous;
#[path = "postgres_contract/api_key.rs"]
mod api_key;
#[path = "postgres_contract/audit.rs"]
mod audit;
#[path = "postgres_contract/guest_capability.rs"]
mod guest_capability;
#[path = "postgres_contract/magic_link.rs"]
mod magic_link;
#[path = "postgres_contract/oauth.rs"]
mod oauth;
#[path = "postgres_contract/operator_security.rs"]
mod operator_security;
#[path = "postgres_contract/organization.rs"]
mod organization;
#[path = "postgres_contract/passkey.rs"]
mod passkey;
#[path = "postgres_contract/rate_limit.rs"]
mod rate_limit;
#[path = "postgres_contract/schema.rs"]
mod schema;
#[path = "postgres_contract/step_up.rs"]
mod step_up;
#[path = "postgres_contract/two_factor.rs"]
mod two_factor;
#[path = "postgres_contract/user_deletion.rs"]
mod user_deletion;
#[path = "postgres_contract/verification.rs"]
mod verification;

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
    migration_checksum_upgrade_is_safe(&store, &pool).await?;
    store.migrate().await?;
    plugin_migrations_are_idempotent(&store, &pool).await?;
    assert_extension_tables_absent(&pool).await?;
    oauth::assert_issuer_qualified_accounts(&store, &pool).await?;

    let (service, api_keys) = contract_service(&store)?;
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Example Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await?;
    migrate_legacy_extensions(&service, &store, &pool, user.id).await?;
    anonymous::assert_lifecycle(&service, &store).await?;
    let signed_in = authenticate_owner(&service, &user).await?;
    organization::assert_persistence(&service, &store, &signed_in.session).await?;
    admin::assert_query_and_update(&service, &signed_in.session).await?;
    account_update::assert_persistence(&service, &store, &signed_in.session, &pool).await?;
    let step_up_session = step_up::authenticate_fixture(&service, &store).await?;
    step_up::assert_atomic(&service, &store, &pool, &step_up_session).await?;

    verification::values_are_atomic(&store, user.id).await?;
    verification::email_is_atomic(&store, &user).await?;
    verification::password_reset_is_atomic(&store, &pool, user.id).await?;
    magic_link::assert_promotion_is_atomic(&store, &pool).await?;
    email_signup_is_case_insensitive(&service, &pool).await?;
    username_signup_is_atomic(&service, &pool).await?;
    guest_capability::assert_atomic(&store, &service, &pool, &signed_in.session).await?;
    user_deletion::assert_transactional(&service, &pool).await?;
    passkey_counters_are_atomic(&store, user.id).await?;
    rate_limit::assert_atomic(&store, &pool).await?;
    two_factor::assert_atomic(&store, &pool, user.id).await?;
    api_key::assert_limits_are_atomic(&service, &api_keys, &signed_in.session).await?;
    audit::assert_retention_is_atomic(&store, &pool, user.id).await?;
    operator_security::assert_atomic(&service, &store, &signed_in, user.id).await?;
    schema::assert_clean_and_detects_drift(&store, &pool, &service.plugin_migrations()).await?;
    schema::session_token_upgrade_invalidates_incompatible_hashes(&store, &pool).await?;

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await?;
    admin.close().await;
    Ok(())
}

async fn migration_checksum_upgrade_is_safe(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query("DELETE FROM lucid_auth_migrations WHERE version = 18")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE lucid_auth_migrations DROP COLUMN checksum")
        .execute(pool)
        .await?;
    store.migrate().await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_migrations WHERE checksum IS NULL",
        )
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

fn contract_service(
    store: &Arc<PostgresStore>,
) -> Result<(Arc<AuthService>, lucid_auth::ApiKeyConfiguration), AuthError> {
    let mut config = AuthConfig::new([42_u8; 32])?;
    config.email_and_password.enabled = true;
    config.user.delete_user.enabled = true;
    config.user.additional_fields.insert(
        "timezone".into(),
        AdditionalField::new(AdditionalFieldType::String).optional(),
    );
    config.user.additional_fields.insert(
        "department".into(),
        AdditionalField::new(AdditionalFieldType::String).optional(),
    );
    config.session.additional_fields.insert(
        "theme".into(),
        AdditionalField::new(AdditionalFieldType::String).optional(),
    );
    config.add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))?;
    config.add_plugin(AnonymousPlugin::default())?;
    register_contract_plugins(&mut config, store)?;
    let api_keys = api_key::register(&mut config)?;
    Ok((Arc::new(AuthService::new(store.clone(), config)), api_keys))
}

fn register_contract_plugins(
    config: &mut AuthConfig,
    store: &Arc<PostgresStore>,
) -> Result<(), AuthError> {
    config.add_plugin(OwnerPolicyPlugin)?;
    config.add_plugin(UsernamePlugin::default())?;
    config.add_plugin(PasskeyPlugin::new(PasskeyConfig::default()))?;
    config.add_plugin(GuestCapabilityPlugin::new(store.clone()))?;
    config.add_plugin(AuditPlugin::new(store.clone()).with_max_events(100))?;
    config.add_plugin(TwoFactorPlugin::new(
        store.clone(),
        TwoFactorConfig::default(),
    ))?;
    config.add_plugin(StepUpPolicyPlugin::new(
        store.clone(),
        store.clone(),
        StepUpPolicyConfig {
            required_roles: vec!["step-up-test".into()],
            ..StepUpPolicyConfig::default()
        },
    ))?;
    config.add_plugin(OperatorSecurityPlugin::new(
        store.clone(),
        OperatorSecurityConfig::default(),
    ))?;
    config.add_plugin(OrganizationPlugin::with_config(
        store.clone(),
        OrganizationPluginConfig {
            teams: OrganizationTeamsConfig {
                enabled: true,
                ..OrganizationTeamsConfig::default()
            },
            dynamic_access_control: OrganizationDynamicAccessControlConfig {
                enabled: true,
                ..OrganizationDynamicAccessControlConfig::default()
            },
            ..OrganizationPluginConfig::default()
        },
    ))?;
    Ok(())
}

async fn migrate_legacy_extensions(
    service: &AuthService,
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let passkey = insert_legacy_passkey(pool, user_id).await?;
    let guest = guest_capability::insert_legacy_shape(pool, user_id).await?;
    let audit = audit::insert_legacy_shape(pool, user_id).await?;
    let step_up = step_up::insert_legacy_shape(pool, user_id).await?;
    let operator = service
        .provision_password_user(NewPasswordUser {
            username: "legacy_operator".into(),
            name: "Legacy Operator State".into(),
            email: None,
            password: "legacy operator password".into(),
            role: "member".into(),
        })
        .await?;
    operator_security::insert_legacy_shape(pool, operator.id).await?;
    store.migrate_plugins(&service.plugin_migrations()).await?;
    store.migrate_plugins(&service.plugin_migrations()).await?;
    assert_eq!(passkey_public_key_column_count(pool).await?, 1);
    assert_legacy_passkey_migrated(store, &passkey).await?;
    guest_capability::assert_legacy_migrated(pool, guest).await?;
    audit::assert_legacy_migrated(store, pool, audit).await?;
    step_up::assert_legacy_migrated(store, pool, step_up).await?;
    operator_security::assert_legacy_migrated(service, pool, operator.id).await?;
    Ok(())
}

async fn assert_extension_tables_absent(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(passkey_public_key_column_count(pool).await?, 0);
    api_key::assert_table_absent(pool).await?;
    audit::assert_table_absent(pool).await?;
    two_factor::assert_table_absent(pool).await?;
    step_up::assert_tables_absent(pool).await?;
    operator_security::assert_table_absent(pool).await?;
    organization::assert_table_absent(pool).await?;
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_guest_grants') IS NOT NULL")
            .fetch_one(pool)
            .await?
    );
    Ok(())
}

async fn authenticate_owner(
    service: &AuthService,
    user: &AuthUser,
) -> Result<lucid_auth::SignInResult, AuthError> {
    let signed_in = service
        .sign_in_username(
            "owner",
            "correct horse battery staple".into(),
            Some("127.0.0.1".into()),
            Some("lucid-auth integration test".into()),
        )
        .await?;
    assert_eq!(&signed_in.session.user, user);
    assert_eq!(signed_in.session.principal().subject_id, user.id);
    assert!(service.session(&signed_in.token).await?.is_some());
    Ok(signed_in)
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
        additional_fields: serde_json::Map::new(),
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
        additional_fields: serde_json::Map::new(),
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
