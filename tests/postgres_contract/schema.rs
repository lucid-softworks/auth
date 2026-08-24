use lucid_auth::{
    PluginMigrationContribution,
    postgres::{
        PostgresMigrationDescriptor, PostgresMigrationPlan, PostgresSchemaIssue,
        PostgresSchemaObject, PostgresStore,
    },
};

pub async fn assert_clean_and_detects_drift(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    migrations: &[PluginMigrationContribution],
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = PostgresStore::migration_plan(migrations)?;
    assert_generated_objects(&plan);
    let report = store.diagnose_schema(migrations).await?;
    assert!(report.compatible, "unexpected schema issues: {report:?}");
    assert!(report.pending_migrations.is_empty());
    let serialized = serde_json::to_string(&report)?;
    assert!(!serialized.contains("postgres://"));
    assert!(!serialized.to_ascii_lowercase().contains("password"));

    detect_index_drift(store, pool, migrations).await?;
    detect_column_drift(store, pool, migrations).await?;
    detect_migration_drift(store, pool, migrations, &plan).await?;

    let report = store.diagnose_schema(migrations).await?;
    assert!(report.compatible, "schema did not recover: {report:?}");
    Ok(())
}

fn assert_generated_objects(plan: &PostgresMigrationPlan) {
    assert!(plan.schema.contains(&PostgresSchemaObject::Column {
        table: "lucid_auth_accounts".into(),
        name: "additional_fields".into(),
        data_type: "jsonb".into(),
    }));
    assert!(plan.schema.contains(&PostgresSchemaObject::Index {
        table: "lucid_auth_api_keys".into(),
        name: "lucid_auth_api_keys_expiry_idx".into(),
        unique: false,
    }));
}

async fn detect_index_drift(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    migrations: &[PluginMigrationContribution],
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query("DROP INDEX lucid_auth_api_keys_expiry_idx")
        .execute(pool)
        .await?;
    let report = store.diagnose_schema(migrations).await?;
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        PostgresSchemaIssue::MissingIndex { table, index }
            if table == "lucid_auth_api_keys" && index == "lucid_auth_api_keys_expiry_idx"
    )));
    sqlx::query("CREATE INDEX lucid_auth_api_keys_expiry_idx ON lucid_auth_api_keys(expires_at)")
        .execute(pool)
        .await?;
    Ok(())
}

async fn detect_column_drift(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    migrations: &[PluginMigrationContribution],
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query("ALTER TABLE lucid_auth_two_factors DROP COLUMN last_totp_counter")
        .execute(pool)
        .await?;
    let report = store.diagnose_schema(migrations).await?;
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        PostgresSchemaIssue::MissingColumn { table, column }
            if table == "lucid_auth_two_factors" && column == "last_totp_counter"
    )));
    sqlx::query("ALTER TABLE lucid_auth_two_factors ADD COLUMN last_totp_counter BIGINT")
        .execute(pool)
        .await?;
    Ok(())
}

async fn detect_migration_drift(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    migrations: &[PluginMigrationContribution],
    plan: &PostgresMigrationPlan,
) -> Result<(), Box<dyn std::error::Error>> {
    let core_checksum = core_checksum(plan);
    sqlx::query("UPDATE lucid_auth_migrations SET checksum = 'tampered' WHERE version = 1")
        .execute(pool)
        .await?;
    let report = store.diagnose_schema(migrations).await?;
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        PostgresSchemaIssue::MigrationChecksumMismatch { migration, .. }
            if migration == "core:1"
    )));
    let error = store.migrate().await.unwrap_err().to_string();
    assert!(error.contains("checksum"));
    assert!(!error.contains("postgres://"));
    sqlx::query("UPDATE lucid_auth_migrations SET checksum = $1 WHERE version = 1")
        .bind(core_checksum)
        .execute(pool)
        .await?;

    sqlx::query(
        "INSERT INTO lucid_auth_migrations (version, description, checksum) \
         VALUES (999, 'future migration', 'future')",
    )
    .execute(pool)
    .await?;
    let report = store.diagnose_schema(migrations).await?;
    assert!(
        report
            .issues
            .contains(&PostgresSchemaIssue::UnknownCoreMigration { version: 999 })
    );
    sqlx::query("DELETE FROM lucid_auth_migrations WHERE version = 999")
        .execute(pool)
        .await?;
    Ok(())
}

fn core_checksum(plan: &PostgresMigrationPlan) -> String {
    plan.migrations
        .iter()
        .find_map(|migration| match migration {
            PostgresMigrationDescriptor::Core {
                version: 1,
                checksum,
                ..
            } => Some(checksum.clone()),
            _ => None,
        })
        .expect("core migration 1 is planned")
}
