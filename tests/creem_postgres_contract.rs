#![cfg(feature = "postgres")]

use chrono::Utc;
use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, AuthStore, AuthUser, CreemModelSchema, CreemSchema,
    CreemStore, CreemSubscription, CreemSubscriptionPatch, DatabaseCreate, DatabaseIdGeneration,
    DatabaseIdInput, DatabaseIdPlan, PluginDescriptor, PluginProvenance, PluginSchemaTable,
    PostgresCreemStore, creem_schema_tables, postgres::PostgresStore,
};
use serde_json::{Map, Value};
use sqlx::postgres::PgPoolOptions;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use uuid::Uuid;

struct SchemaPlugin(CreemSchema);

#[async_trait::async_trait]
impl AuthPlugin for SchemaPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "creem-postgres-contract",
            display_name: "Creem PostgreSQL Contract",
            version: "1",
            provenance: PluginProvenance::LucidExtension,
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        creem_schema_tables(&self.0, true).unwrap()
    }
}

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
        let postgres = PostgresStore::new(pool.clone(), Default::default());
        let mut config = AuthConfig::new([55; 32])?;
        config.add_plugin(SchemaPlugin(remapped_schema()))?;
        let _service = AuthService::new(Arc::new(postgres.clone()), config);
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
    Ok(PostgresCreemStore::new(fixture.postgres.clone()))
}

async fn assert_real_user_updates(
    postgres: &PostgresStore,
    store: &PostgresCreemStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let user = postgres
        .create_user_without_account(user_create(user()))
        .await?;
    store.set_user_customer_id(&user.id, "customer").await?;
    store.set_user_had_trial(&user.id, true).await?;
    let stored_user = store
        .find_user(&user.id)
        .await?
        .expect("core user remains visible to Creem");
    assert_eq!(
        stored_user.creem_customer_id,
        Some(Value::String("customer".into()))
    );
    assert_eq!(stored_user.had_trial, Some(Value::Bool(true)));
    let core_user = postgres.find_user_by_id(&user.id).await?.unwrap();
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
        id: String::new(),
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

fn user_create(user: AuthUser) -> DatabaseCreate<AuthUser> {
    DatabaseCreate::new(
        user,
        DatabaseIdPlan::new(
            DatabaseIdGeneration::Default,
            "user",
            DatabaseIdInput::Absent,
            false,
        ),
    )
}
