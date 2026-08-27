use chrono::{Duration, Utc};
use lucid_auth::{
    AuthConfig, AuthService, DatabaseCreate, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan,
    DeviceAuthorizationConfig, DeviceAuthorizationModelSchema, DeviceAuthorizationSchema,
    DeviceAuthorizationStore, DeviceCode, DeviceCodeCreateOutcome, DeviceCodeOwner,
    DeviceCodeStatus, NewPasswordUser, OAuthDeviceAuthorizationPlugin, OAuthProviderPlugin,
    OAuthProviderPluginConfig,
    postgres::{
        PostgresAdapterConfig, PostgresDeviceAuthorizationStore, PostgresSchemaObject,
        PostgresStore,
    },
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

#[path = "device_authorization_schema/atomic.rs"]
mod atomic;
#[path = "device_authorization_schema/fixtures.rs"]
mod fixtures;
#[path = "device_authorization_schema/round_trip.rs"]
mod round_trip;

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn remapped_schema_migrates_idempotently_and_preserves_atomic_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let database_schema = format!("lucid_auth_device_schema_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {database_schema}"))
        .execute(&admin)
        .await?;

    let search_path = format!("SET search_path TO {database_schema}");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(&search_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await?;
    let postgres = PostgresStore::new(pool.clone(), PostgresAdapterConfig { use_plural: true });
    let schema = mapped_schema();
    let mut config = DeviceAuthorizationConfig::default();
    config.schema = schema;
    let plugin = OAuthDeviceAuthorizationPlugin::postgres(config, postgres.clone());
    let mut auth = AuthConfig::new([52; 32])?;
    auth.database_id_generation = DatabaseIdGeneration::Serial;
    let mut provider_config = OAuthProviderPluginConfig::new("/login", "/consent");
    provider_config.disable_jwt_plugin = true;
    auth.add_plugin(OAuthProviderPlugin::postgres(
        provider_config,
        postgres.clone(),
    )?)?;
    auth.add_plugin(plugin)?;
    let service = AuthService::new(Arc::new(postgres.clone()), auth);
    let plan = postgres.migration_plan(&[])?;
    let table = "Device Code Recordss";
    for name in [
        "device value",
        "user\"value",
        "poll milliseconds",
        "resources",
        "oauthClientId",
    ] {
        assert!(plan.schema.iter().any(|object| matches!(
            object,
            PostgresSchemaObject::Column { table: actual_table, name: actual_name, .. }
                if actual_table == table && actual_name == name
        )));
    }
    assert!(!format!("{:?}", plan.schema).contains("lucid_auth_device_codes"));
    assert!(!format!("{:?}", plan.schema).contains("created_at"));
    assert!(!format!("{:?}", plan.schema).contains("updated_at"));
    postgres.migrate().await?;
    postgres.migrate().await?;
    let device_codes = PostgresDeviceAuthorizationStore::new(postgres.clone());
    let users = provision_users(&service).await?;

    assert_id_storage(&pool).await?;
    round_trip::all_fields_and_unique_codes(&device_codes, &postgres, &users[0]).await?;
    atomic::claim_and_consume_are_single_winner(&device_codes, &postgres, &users).await?;

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {database_schema} CASCADE"))
        .execute(&admin)
        .await?;
    Ok(())
}

fn mapped_schema() -> DeviceAuthorizationSchema {
    let mut fields = std::collections::BTreeMap::new();
    for (logical, physical) in [
        ("deviceCode", "device value"),
        ("userCode", "user\"value"),
        ("userId", "owner user"),
        ("expiresAt", "expires on"),
        ("status", "request status"),
        ("lastPolledAt", "last poll"),
        ("pollingInterval", "poll milliseconds"),
        ("clientId", "standalone client"),
        ("scope", "granted scope"),
    ] {
        fields.insert(logical.into(), physical.into());
    }
    DeviceAuthorizationSchema {
        device_code: DeviceAuthorizationModelSchema {
            model_name: Some("Device Code Records".into()),
            fields,
        },
    }
}

async fn assert_id_storage(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let types = sqlx::query_as::<_, (String, String)>(
        "SELECT column_name, data_type FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = 'Device Code Recordss' \
           AND column_name IN ('id', 'owner user') ORDER BY column_name",
    )
    .fetch_all(pool)
    .await?;
    assert_eq!(
        types,
        [
            ("id".into(), "integer".into()),
            ("owner user".into(), "text".into())
        ]
    );
    Ok(())
}

async fn provision_users(service: &AuthService) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut ids = Vec::new();
    for suffix in ["one", "two", "three"] {
        let user = service
            .provision_password_user(NewPasswordUser {
                username: format!("device_{suffix}"),
                name: format!("Device {suffix}"),
                email: Some(format!("device-{suffix}@example.com")),
                password: "correct horse battery staple".into(),
                role: "user".into(),
            })
            .await?;
        ids.push(user.id);
    }
    Ok(ids)
}
fn code(suffix: &str, user_id: Option<String>) -> DeviceCode {
    DeviceCode {
        id: String::new(),
        device_code: format!("device-{suffix}"),
        user_code: format!("USER-{suffix}"),
        user_id,
        expires_at: Utc::now() + Duration::minutes(30),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
        polling_interval: Some(5_000.0),
        client_id: Some("standalone-client".into()),
        scope: Some("openid profile".into()),
        resources: Some(vec!["https://api.example".into()]),
        oauth_client_id: Some("oauth-client".into()),
    }
}

fn create(code: DeviceCode) -> DatabaseCreate<DeviceCode> {
    DatabaseCreate::new(
        code,
        DatabaseIdPlan::new(
            DatabaseIdGeneration::Serial,
            "deviceCode",
            DatabaseIdInput::Absent,
            false,
        ),
    )
}
