use chrono::{Duration, Utc};
use lucid_auth::{
    AuthConfig, AuthService, NewPasswordUser, PluginMigration, PluginMigrationContribution,
    VerificationStore, VerificationValue, postgres::PostgresStore,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

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
        .fetch_one(&pool)
        .await?,
        1
    );

    let service = AuthService::new(store.clone(), AuthConfig::new([42_u8; 32])?);
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Example Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await?;
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

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await?;
    admin.close().await;
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
