use lucid_auth::{
    PluginMigrationContribution,
    postgres::{PostgresMigrationPlan, PostgresSchemaIssue, PostgresSchemaObject, PostgresStore},
};

pub(super) async fn assert_extension_tables_absent(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    super::api_key::assert_exact_schema(pool).await?;
    super::two_factor::assert_exact_schema(pool).await?;
    super::audit::assert_table_absent(pool).await?;
    super::step_up::assert_tables_absent(pool).await?;
    super::operator_security::assert_table_absent(pool).await?;
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_guest_grants') IS NOT NULL")
            .fetch_one(pool)
            .await?
    );
    Ok(())
}

pub async fn assert_clean_and_detects_drift(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    migrations: &[PluginMigrationContribution],
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = store.migration_plan(migrations)?;
    assert_generated_objects(&plan);
    let report = store.diagnose_schema(migrations).await?;
    assert!(report.compatible, "unexpected schema issues: {report:?}");
    assert!(report.pending_migrations.is_empty());
    let serialized = serde_json::to_string(&report)?;
    assert!(!serialized.contains("postgres://"));
    assert!(!serialized.to_ascii_lowercase().contains("password"));

    detect_index_drift(store, pool, migrations).await?;
    detect_column_drift(store, pool, migrations).await?;

    let report = store.diagnose_schema(migrations).await?;
    assert!(report.compatible, "schema did not recover: {report:?}");
    Ok(())
}

fn assert_generated_objects(plan: &PostgresMigrationPlan) {
    assert!(plan.schema.contains(&PostgresSchemaObject::Column {
        table: "user".into(),
        name: "email".into(),
        data_type: "text".into(),
    }));
    assert!(plan.schema.contains(&PostgresSchemaObject::Index {
        table: "account".into(),
        name: "account_issuer_accountId_uidx".into(),
        unique: true,
    }));
}

async fn detect_index_drift(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    migrations: &[PluginMigrationContribution],
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query("DROP INDEX \"account_issuer_accountId_uidx\"")
        .execute(pool)
        .await?;
    let report = store.diagnose_schema(migrations).await?;
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        PostgresSchemaIssue::MissingIndex { table, index }
            if table == "account" && index == "account_issuer_accountId_uidx"
    )));
    sqlx::query(
        "CREATE UNIQUE INDEX \"account_issuer_accountId_uidx\" \
         ON \"account\" (\"issuer\", \"accountId\")",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn detect_column_drift(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    migrations: &[PluginMigrationContribution],
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query("ALTER TABLE \"user\" DROP COLUMN \"timezone\"")
        .execute(pool)
        .await?;
    let report = store.diagnose_schema(migrations).await?;
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        PostgresSchemaIssue::MissingColumn { table, column }
            if table == "user" && column == "timezone"
    )));
    sqlx::query("ALTER TABLE \"user\" ADD COLUMN \"timezone\" TEXT")
        .execute(pool)
        .await?;
    Ok(())
}
