#![cfg(feature = "postgres")]

use chrono::{Duration, Utc};
use lucid_auth::{
    AuthConfig, DatabaseScimStore, ScimManagedConnectionOptions, ScimOptions, ScimPlugin,
    ScimScope,
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn managed_scim_catalog_is_transactional_on_postgres()
-> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let schema = format!("lucid_auth_scim_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await?;
    let search_path = format!("SET search_path TO {schema}");
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
    let auth_store = Arc::new(PostgresStore::new(
        pool.clone(),
        PostgresAdapterConfig::default(),
    ));
    let scim_store = Arc::new(DatabaseScimStore::new(auth_store.clone()));
    let plugin = ScimPlugin::new(
        ScimOptions {
            managed_connections: Some(ScimManagedConnectionOptions::new("p".repeat(32))),
            ..ScimOptions::default()
        },
        scim_store,
    )?;
    let mut config = AuthConfig::new([207_u8; 32])?;
    config.add_plugin(plugin.clone())?;
    let _service = lucid_auth::AuthService::new(auth_store.clone(), config);
    auth_store.migrate().await?;

    let expires_at = Utc::now() + Duration::hours(1);
    let create = || {
        plugin.create_managed_connection(
            "postgres-request-0001",
            "postgres-domain",
            "operator",
            ScimScope::ALL.to_vec(),
            expires_at,
        )
    };
    let (first, second) = tokio::join!(create(), create());
    let conflicts = [&first, &second]
        .into_iter()
        .filter(|result| result.as_ref().is_err_and(|error| error.status == 409))
        .count();
    assert_eq!(conflicts, 1, "first={first:?}, second={second:?}");
    let (connection, credential, _) = first
        .ok()
        .or_else(|| second.ok())
        .expect("one concurrent creation wins");

    let (rotated_connection, rotated, _) = plugin
        .rotate_managed_credential(
            &connection.connection_id,
            "postgres-domain",
            "operator",
            ScimScope::ALL.to_vec(),
            expires_at,
        )
        .await?;
    assert_eq!(rotated_connection.revision, 3);
    plugin
        .revoke_managed_credential(
            &connection.connection_id,
            "postgres-domain",
            &credential.credential_id,
            "operator",
        )
        .await?;
    let events = plugin
        .list_managed_connection_events(&connection.connection_id, "postgres-domain")
        .await?;
    assert_eq!(events.len(), 4);
    assert_eq!(rotated.status, "active");

    let (retired, credentials) = plugin
        .decommission_managed_connection(&connection.connection_id, "postgres-domain", "operator")
        .await?;
    assert_eq!(retired.status, "decommissioned");
    assert!(credentials.iter().all(|item| item.status != "active"));

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await?;
    admin.close().await;
    Ok(())
}
