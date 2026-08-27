use super::*;
use lucid_auth::JwtSchema;

pub(super) async fn assert_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let database = StrategyDatabase::start(DatabaseIdGeneration::Database, "database").await?;
    prepare_database_defaults(&database).await?;
    let plan = DatabaseIdPlan::new(
        DatabaseIdGeneration::Database,
        "twoFactor",
        DatabaseIdInput::Absent,
        false,
    );
    let stored = database
        .store
        .upsert_two_factor(
            &|| plan.prepare(database.store.as_ref()),
            two_factor_record("database-user", "database-secret"),
        )
        .await?;
    assert_eq!(stored.id, "database-two-factor-id");
    assert_eq!(stored.user_id, "database-user");
    assert_jwk_round_trip(&database).await?;
    assert_device_round_trip(&database).await?;
    plugin_round_trip::assert_database_round_trip(&database).await?;
    organization_database::assert_round_trip(&database).await?;
    let oauth = oauth_provider_database::assert_round_trip(&database).await?;
    for id in oauth.all() {
        assert!(id.starts_with("database-oauth-"));
    }
    assert_two_factor_physical_types(&database).await?;
    database.close().await?;
    organization_database::assert_empty_callback_defer().await
}

async fn prepare_database_defaults(
    database: &StrategyDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        r#"INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt")
           VALUES ('database-user', 'Database User', 'database@example.com', false, NOW(), NOW())"#,
    )
    .execute(&database.pool)
    .await?;
    sqlx::query(r#"ALTER TABLE "twoFactor" ALTER COLUMN id SET DEFAULT 'database-two-factor-id'"#)
        .execute(&database.pool)
        .await?;
    sqlx::query(r#"ALTER TABLE "jwks" ALTER COLUMN id SET DEFAULT 'database-jwks-id'"#)
        .execute(&database.pool)
        .await?;
    sqlx::query(
        r#"ALTER TABLE "deviceCode" ALTER COLUMN id SET DEFAULT 'database-device-code-id'"#,
    )
    .execute(&database.pool)
    .await?;
    sqlx::query(
        r#"ALTER TABLE "verification" ALTER COLUMN id SET DEFAULT 'database-verification-id'"#,
    )
    .execute(&database.pool)
    .await?;
    Ok(())
}

async fn assert_jwk_round_trip(
    database: &StrategyDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    let jwks = database
        .service
        .jwt()
        .expect("strategy fixture installs JWT")
        .create_jwk(&JwtAdapterContext::default(), None)
        .await?;
    assert_eq!(jwks.id, "database-jwks-id");
    assert_eq!(
        database
            .store
            .list_jwks(&JwtSchema::default())
            .await?
            .first()
            .map(|key| key.id.as_str()),
        Some("database-jwks-id")
    );
    Ok(())
}

async fn assert_device_round_trip(
    database: &StrategyDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    let device = device_code::create(
        database,
        "database",
        "database-user",
        &DatabaseIdGeneration::Database,
    )
    .await?;
    assert_eq!(device.id, "database-device-code-id");
    assert_eq!(device.user_id.as_deref(), Some("database-user"));
    device_code::assert_physical_types(database, &device.id, "text").await
}

async fn assert_two_factor_physical_types(
    database: &StrategyDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    let physical = sqlx::query_as::<_, (String, String)>(
        r#"SELECT pg_typeof(id)::text, pg_typeof("userId")::text FROM "twoFactor""#,
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!(physical, ("text".into(), "text".into()));
    Ok(())
}
