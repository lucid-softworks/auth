#![cfg(feature = "postgres")]

use chrono::Utc;
use lucid_auth::{
    AuthStore, AuthUser, CreemModelSchema, CreemSchema, CreemStore, CreemSubscription,
    CreemSubscriptionPatch, PluginMigrationContribution, PostgresCreemStore, creem_migration,
    postgres::PostgresStore,
};
use serde_json::{Map, Value};
use sqlx::postgres::PgPoolOptions;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn remapped_storage_preserves_creem_adapter_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = DatabaseFixture::start().await?;
    let store = migrate_creem(&fixture).await?;
    assert_real_user_updates(&fixture.postgres, &store).await?;
    assert_subscription_boundaries(&store).await?;
    fixture.finish().await?;
    Ok(())
}

struct DatabaseFixture {
    database_schema: String,
    admin: sqlx::PgPool,
    pool: sqlx::PgPool,
    postgres: PostgresStore,
}

impl DatabaseFixture {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let database_url = std::env::var("DATABASE_URL")?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;
        let database_schema = format!("lucid_auth_creem_{}", Uuid::new_v4().simple());
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
        Ok(Self {
            database_schema,
            admin,
            pool,
            postgres,
        })
    }

    async fn finish(self) -> Result<(), Box<dyn std::error::Error>> {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.database_schema))
            .execute(&self.admin)
            .await?;
        self.admin.close().await;
        Ok(())
    }
}

async fn migrate_creem(
    fixture: &DatabaseFixture,
) -> Result<PostgresCreemStore, Box<dyn std::error::Error>> {
    let schema = remapped_schema();
    let store = PostgresCreemStore::new(fixture.postgres.clone(), &schema, true)?;
    let migration = creem_migration(&schema, true)?;
    let contributions = [PluginMigrationContribution {
        plugin_id: "creem-postgres-contract",
        migration,
    }];
    fixture.postgres.migrate_plugins(&contributions).await?;
    fixture.postgres.migrate_plugins(&contributions).await?;
    assert_migration_shape(&fixture.pool, store.migration_sql()).await?;
    Ok(store)
}

async fn assert_real_user_updates(
    postgres: &PostgresStore,
    store: &PostgresCreemStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let user = user();
    postgres.create_user_without_account(user.clone()).await?;
    store
        .set_user_customer_id(&user.id.to_string(), "customer")
        .await?;
    store.set_user_had_trial(&user.id.to_string(), true).await?;
    let stored_user = store
        .find_user(&user.id.to_string())
        .await?
        .expect("core user remains visible to Creem");
    assert_eq!(
        stored_user.creem_customer_id,
        Some(Value::String("customer".into()))
    );
    assert_eq!(stored_user.had_trial, Some(Value::Bool(true)));
    let core_user = postgres.find_user_by_id(user.id).await?.unwrap();
    assert_eq!(
        core_user.additional_fields.get("creemCustomerId"),
        Some(&Value::String("customer".into()))
    );
    Ok(())
}

async fn assert_subscription_boundaries(
    store: &PostgresCreemStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let first = subscription("external-owner", "duplicate");
    let second = subscription("external-owner", "duplicate");
    store.create_subscription(first.clone()).await?;
    store.create_subscription(second.clone()).await?;
    let ids = store
        .list_subscriptions_by_reference("external-owner")
        .await?
        .into_iter()
        .map(|row| row.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(ids, BTreeSet::from([first.id, second.id]));
    assert!(
        store
            .find_subscription_by_creem_id("duplicate")
            .await?
            .is_some()
    );

    let period_end = Utc::now();
    let updated = store
        .update_subscription(
            first.id,
            CreemSubscriptionPatch {
                product_id: Some("replacement-product".into()),
                reference_id: Some("replacement-owner".into()),
                creem_order_id: Some(Some("replacement-order".into())),
                status: Some("provider-specific-status".into()),
                period_end: Some(Some(period_end)),
                ..CreemSubscriptionPatch::default()
            },
        )
        .await?
        .unwrap();
    assert_eq!(updated.reference_id, "replacement-owner");
    assert_eq!(updated.status, "provider-specific-status");
    assert_eq!(updated.period_end, Some(period_end));
    assert!(updated.cancel_at_period_end);
    Ok(())
}

fn remapped_schema() -> CreemSchema {
    let mut schema = CreemSchema::default();
    schema.insert_model(
        "creem_subscription",
        CreemModelSchema {
            model_name: Some("creem billing rows".into()),
            fields: BTreeMap::from([
                ("productId".into(), "product key".into()),
                ("referenceId".into(), "owner key".into()),
                ("creemSubscriptionId".into(), "provider key".into()),
            ]),
        },
    );
    schema
}

async fn assert_migration_shape(
    pool: &sqlx::PgPool,
    migration_sql: &str,
) -> Result<(), sqlx::Error> {
    assert!(migration_sql.contains("CREATE TABLE IF NOT EXISTS \"creem billing rows\""));
    assert!(!migration_sql.contains("UNIQUE"));
    assert!(!migration_sql.contains("REFERENCES"));
    assert!(!migration_sql.contains("CREATE INDEX"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.table_constraints \
             WHERE table_schema = current_schema() AND table_name = 'creem billing rows' \
               AND constraint_type = 'FOREIGN KEY'",
        )
        .fetch_one(pool)
        .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() \
             AND tablename = 'creem billing rows' AND indexdef NOT LIKE '%UNIQUE%'",
        )
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

fn subscription(reference_id: &str, provider_id: &str) -> CreemSubscription {
    let mut subscription = CreemSubscription::new("product", reference_id);
    subscription.creem_customer_id = Some("customer".into());
    subscription.creem_subscription_id = Some(provider_id.into());
    subscription.status = "Raw_Status".into();
    subscription.cancel_at_period_end = true;
    subscription
}

fn user() -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: Uuid::new_v4(),
        username: None,
        display_username: None,
        name: "Creem PostgreSQL user".into(),
        email: "creem-postgres@example.com".into(),
        email_verified: true,
        image: None,
        additional_fields: Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}
