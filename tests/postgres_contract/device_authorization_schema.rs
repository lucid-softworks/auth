use chrono::{Duration, Utc};
use lucid_auth::{
    AuthPlugin, DeviceAuthorizationConfig, DeviceAuthorizationModelSchema,
    DeviceAuthorizationSchema, DeviceAuthorizationStore, DeviceCode, DeviceCodeCreateOutcome,
    DeviceCodeOwner, DeviceCodeStatus, OAuthDeviceAuthorizationPlugin, PluginMigrationContribution,
    postgres::{PostgresDeviceAuthorizationStore, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
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
    let postgres = PostgresStore::new(pool.clone());
    postgres.migrate().await?;

    let schema = mapped_schema();
    let device_codes = PostgresDeviceAuthorizationStore::new(postgres.clone(), &schema, true)?;
    let migration_sql = device_codes.migration_sql();
    assert!(migration_sql.contains("CREATE TABLE IF NOT EXISTS \"Device Code Records\""));
    assert!(migration_sql.contains("\"device value\" TEXT NOT NULL UNIQUE"));
    assert!(migration_sql.contains("\"user\"\"value\" TEXT NOT NULL UNIQUE"));
    assert!(migration_sql.contains("\"poll milliseconds\" DOUBLE PRECISION"));
    assert!(migration_sql.contains("\"resources\" TEXT[]"));
    assert!(migration_sql.contains("\"oauth_client_id\" TEXT"));
    assert!(!migration_sql.contains("REFERENCES"));
    assert!(!migration_sql.contains("created_at"));
    assert!(!migration_sql.contains("updated_at"));
    let mut config = DeviceAuthorizationConfig::default();
    config.schema = schema;
    let plugin = OAuthDeviceAuthorizationPlugin::postgres(config, postgres.clone())?;
    let migrations = plugin
        .migrations()
        .iter()
        .cloned()
        .map(|migration| PluginMigrationContribution {
            plugin_id: "device-authorization",
            migration,
        })
        .collect::<Vec<_>>();
    postgres.migrate_plugins(&migrations).await?;
    postgres.migrate_plugins(&migrations).await?;

    round_trip::all_fields_and_unique_codes(&device_codes).await?;
    atomic::claim_and_consume_are_single_winner(&device_codes).await?;

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

fn code(suffix: &str, user_id: Option<Uuid>) -> DeviceCode {
    DeviceCode {
        id: Uuid::new_v4(),
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
