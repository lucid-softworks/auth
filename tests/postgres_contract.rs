use lucid_auth::{
    AccessStore, AccountDeleteOutcome, AdditionalField, AdditionalFieldType, AdminPlugin,
    AgentAuthConfig, AgentAuthPlugin, AnonymousPlugin, AuditPlugin, AuthConfig, AuthError,
    AuthService, AuthSession, AuthStore, AuthUser, AuthenticationMethod, GuestCapabilityPlugin,
    LastLoginMethodConfig, LastLoginMethodPlugin, MultiSessionPlugin, NewPasswordUser,
    OAuthAccount, OAuthAccountStore, OAuthTokenUpdateOutcome, OperatorSecurityConfig,
    OperatorSecurityPlugin, OrganizationDynamicAccessControlConfig, OrganizationPlugin,
    OrganizationPluginConfig, OrganizationTeamsConfig, OwnerPolicyPlugin, PasskeyConfig,
    PasskeyPlugin, PluginMigration, PluginMigrationContribution, PostgresAgentAuthStore,
    RateLimitStorageMode, StepUpPolicyConfig, StepUpPolicyPlugin, TwoFactorConfig, TwoFactorPlugin,
    UsernamePlugin, postgres::PostgresStore,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

#[path = "postgres_contract/account_update.rs"]
mod account_update;
#[path = "postgres_contract/admin.rs"]
mod admin;
#[path = "postgres_contract/agent_auth.rs"]
mod agent_auth;
#[path = "postgres_contract/anonymous.rs"]
mod anonymous;
#[path = "postgres_contract/api_key.rs"]
mod api_key;
#[path = "postgres_contract/audit.rs"]
mod audit;
#[path = "postgres_contract/chargebee.rs"]
mod chargebee;
#[path = "postgres_contract/device_authorization_schema.rs"]
mod device_authorization_schema;
#[path = "postgres_contract/dodo_payments.rs"]
mod dodo_payments;
#[path = "postgres_contract/electron.rs"]
mod electron;
#[path = "postgres_contract/email_otp.rs"]
mod email_otp;
#[path = "postgres_contract/guest_capability.rs"]
mod guest_capability;
#[path = "postgres_contract/hostile_remap.rs"]
mod hostile_remap;
#[path = "postgres_contract/id_strategies.rs"]
mod id_strategies;
#[path = "postgres_contract/last_login_method.rs"]
mod last_login_method;
#[path = "postgres_contract/magic_link.rs"]
mod magic_link;
#[path = "postgres_contract/mcp.rs"]
mod mcp;
#[path = "postgres_contract/multi_session.rs"]
mod multi_session;
#[path = "postgres_contract/oauth.rs"]
mod oauth;
#[path = "postgres_contract/oauth_provider_schema.rs"]
mod oauth_provider_schema;
#[path = "postgres_contract/operator_security.rs"]
mod operator_security;
#[path = "postgres_contract/organization.rs"]
mod organization;
#[path = "postgres_contract/passkey.rs"]
mod passkey;
#[path = "postgres_contract/phone_number.rs"]
mod phone_number;
#[path = "postgres_contract/rate_limit.rs"]
mod rate_limit;
#[path = "postgres_contract/schema.rs"]
mod schema;
#[path = "postgres_contract/session_refresh.rs"]
mod session_refresh;
#[path = "postgres_contract/signup.rs"]
mod signup;
#[path = "postgres_contract/siwe.rs"]
mod siwe;
#[path = "postgres_contract/step_up.rs"]
mod step_up;
#[path = "postgres_contract/support.rs"]
mod support;
#[path = "postgres_contract/test_utils.rs"]
mod test_utils;
#[path = "postgres_contract/two_factor.rs"]
mod two_factor;
#[path = "postgres_contract/user_deletion.rs"]
mod user_deletion;
#[path = "postgres_contract/verification.rs"]
mod verification;

use passkey::passkey_counters_are_atomic;
use support::*;

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

    let store = Arc::new(PostgresStore::new(
        pool.clone(),
        lucid_auth::postgres::PostgresAdapterConfig::default(),
    ));
    let (service, api_keys, phone_numbers) = contract_service(&store)?;
    store.migrate().await?;
    store.migrate().await?;
    organization::assert_table_absent(&pool).await?;
    plugin_migrations_are_idempotent(&store, &pool).await?;
    schema::assert_extension_tables_absent(&pool).await?;
    store.migrate_plugins(&service.plugin_migrations()).await?;
    store.migrate_plugins(&service.plugin_migrations()).await?;
    oauth::assert_issuer_qualified_accounts(&store, &pool).await?;
    oauth::assert_one_tap_account_and_session_persistence(&store).await?;

    test_utils::assert_persistence(&store, &pool).await?;
    let user = provision_owner(&service).await?;
    run_authentication_contracts(&service, &store, &pool, &user, &api_keys, &phone_numbers).await?;

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await?;
    admin.close().await;
    Ok(())
}

async fn run_authentication_contracts(
    service: &Arc<AuthService>,
    store: &Arc<PostgresStore>,
    pool: &sqlx::PgPool,
    user: &AuthUser,
    api_keys: &lucid_auth::ApiKeyConfiguration,
    phone_numbers: &phone_number::Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    chargebee::assert_migration_and_persistence(service, store, pool, &user.id).await?;
    agent_auth::assert_switch_contract(store, pool, &user.id).await?;
    anonymous::assert_lifecycle(service, store).await?;
    let signed_in = authenticate_owner(service, user).await?;
    dodo_payments::assert_schema_and_persistence(service, store, &user.id).await?;
    electron::assert_round_trip(store, pool, &user.id).await?;
    multi_session::assert_http_round_trip(service).await?;
    last_login_method::assert_http_round_trip(service, store, &user.id).await?;
    session_refresh::assert_atomic(service, store).await?;
    organization::assert_persistence(service, store, &signed_in.session).await?;
    admin::assert_query_and_update(service, &signed_in.session).await?;
    account_update::assert_persistence(service, store, &signed_in.session, pool).await?;
    let step_up_session = step_up::authenticate_fixture(service, store).await?;
    step_up::assert_atomic(service, store, pool, &step_up_session).await?;
    run_atomic_contracts(
        service,
        store,
        pool,
        user,
        api_keys,
        phone_numbers,
        &signed_in,
    )
    .await
}

async fn run_atomic_contracts(
    service: &Arc<AuthService>,
    store: &Arc<PostgresStore>,
    pool: &sqlx::PgPool,
    user: &AuthUser,
    api_keys: &lucid_auth::ApiKeyConfiguration,
    phone_numbers: &phone_number::Fixture,
    signed_in: &lucid_auth::SignInResult,
) -> Result<(), Box<dyn std::error::Error>> {
    verification::values_are_atomic(store, &user.id).await?;
    mcp::assert_durable_dpop_replay(store, pool).await?;
    email_otp::assert_redemption_is_atomic(service, pool).await?;
    phone_number::assert_atomic_and_persistent(service, store, pool, phone_numbers).await?;
    siwe::assert_atomic_and_persistent(service, pool).await?;
    magic_link::assert_promotion_is_atomic(store, pool).await?;
    signup::email_is_case_insensitive(service, pool).await?;
    signup::username_is_atomic(service, pool).await?;
    guest_capability::assert_atomic(store, service, pool, &signed_in.session).await?;
    user_deletion::assert_transactional(service, pool).await?;
    passkey_counters_are_atomic(store, &user.id).await?;
    rate_limit::assert_atomic(store, pool).await?;
    two_factor::assert_atomic(store, pool, &user.id).await?;
    api_key::assert_limits_are_atomic(service, api_keys, &signed_in.session).await?;
    audit::assert_retention_is_atomic(store, pool, &user.id).await?;
    operator_security::assert_atomic(service, store, signed_in, &user.id).await?;
    schema::assert_clean_and_detects_drift(store, pool, &service.plugin_migrations()).await?;
    Ok(())
}

async fn provision_owner(service: &AuthService) -> Result<AuthUser, AuthError> {
    service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Example Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
}

fn contract_service(
    store: &Arc<PostgresStore>,
) -> Result<
    (
        Arc<AuthService>,
        lucid_auth::ApiKeyConfiguration,
        phone_number::Fixture,
    ),
    AuthError,
> {
    let mut config = AuthConfig::new([42_u8; 32])?;
    config.rate_limit.storage = RateLimitStorageMode::Database;
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
    config.account.additional_fields.insert(
        "tenant".into(),
        AdditionalField::new(AdditionalFieldType::String).optional(),
    );
    config.add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))?;
    config.add_plugin(AnonymousPlugin::default())?;
    let phone_numbers = register_contract_plugins(&mut config, store)?;
    let api_keys = api_key::register(&mut config)?;
    Ok((
        Arc::new(AuthService::new(store.clone(), config)),
        api_keys,
        phone_numbers,
    ))
}

fn register_contract_plugins(
    config: &mut AuthConfig,
    store: &Arc<PostgresStore>,
) -> Result<phone_number::Fixture, AuthError> {
    config.add_plugin(chargebee::SchemaPlugin)?;
    config.add_plugin(OwnerPolicyPlugin)?;
    config.add_plugin(UsernamePlugin::default())?;
    config.add_plugin(MultiSessionPlugin::default())?;
    config.add_plugin(LastLoginMethodPlugin::new(LastLoginMethodConfig {
        store_in_database: true,
        ..LastLoginMethodConfig::default()
    }))?;
    email_otp::register(config)?;
    siwe::register(config, store)?;
    let phone_numbers = phone_number::register(config, store)?;
    config.add_plugin(PasskeyPlugin::new(PasskeyConfig::default()))?;
    config.add_plugin(AgentAuthPlugin::new(
        AgentAuthConfig::default(),
        PostgresAgentAuthStore::new(store.as_ref().clone()),
    )?)?;
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
    dodo_payments::register(config, store.clone())?;
    Ok(phone_numbers)
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
        migration: PluginMigration::borrowed(
            "create-records",
            "PostgreSQL contract plugin records",
            "CREATE TABLE lucid_auth_contract_plugin_records (id TEXT PRIMARY KEY)",
        ),
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
