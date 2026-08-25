use chrono::Utc;
use lucid_auth::{
    AuthService, ChargebeeItemType, ChargebeeStore, ChargebeeStoreError, ChargebeeSubscription,
    ChargebeeSubscriptionItem, ChargebeeSubscriptionStatus, NewPasswordUser,
    PluginMigrationContribution, PostgresChargebeeStore, chargebee_migration,
    postgres::PostgresStore,
};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn assert_migration_and_persistence(
    service: &AuthService,
    store: &PostgresStore,
    pool: &PgPool,
    owner_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_conditional_and_idempotent_migrations(store, pool).await?;
    let chargebee = PostgresChargebeeStore::new(store.clone(), true, true);
    assert_customer_linkage_and_uniqueness(service, &chargebee, owner_id).await?;
    assert_subscriptions_and_items(&chargebee, pool).await?;
    Ok(())
}

async fn assert_conditional_and_idempotent_migrations(
    store: &PostgresStore,
    pool: &PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let customer_only = chargebee_migration(false, false);
    sqlx::raw_sql(customer_only.sql.as_ref())
        .execute(pool)
        .await?;
    sqlx::raw_sql(customer_only.sql.as_ref())
        .execute(pool)
        .await?;
    assert!(
        table_name(pool, "lucid_auth_chargebee_subscriptions")
            .await?
            .is_none()
    );

    let enabled = PluginMigrationContribution {
        plugin_id: "chargebee-postgres-contract",
        migration: chargebee_migration(true, false),
    };
    store
        .migrate_plugins(std::slice::from_ref(&enabled))
        .await?;
    store
        .migrate_plugins(std::slice::from_ref(&enabled))
        .await?;
    assert!(
        table_name(pool, "lucid_auth_chargebee_subscriptions")
            .await?
            .is_some()
    );
    assert_eq!(
        migration_count(pool, enabled.migration.id.as_ref()).await?,
        1
    );

    assert_eq!(organization_customer_column_count(pool).await?, 0);
    let organization = chargebee_migration(false, true);
    sqlx::raw_sql(organization.sql.as_ref())
        .execute(pool)
        .await?;
    sqlx::raw_sql(organization.sql.as_ref())
        .execute(pool)
        .await?;
    assert_eq!(organization_customer_column_count(pool).await?, 1);
    sqlx::query("DELETE FROM lucid_auth_plugin_migrations WHERE plugin_id = $1")
        .bind(enabled.plugin_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn assert_customer_linkage_and_uniqueness(
    service: &AuthService,
    store: &PostgresChargebeeStore,
    owner_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    store
        .set_user_customer_id(owner_id, Some("chargebee_customer_owner".into()))
        .await?;
    assert_eq!(
        store.user_customer_id(owner_id).await?.as_deref(),
        Some("chargebee_customer_owner")
    );
    assert_eq!(
        store
            .user_id_by_customer("chargebee_customer_owner")
            .await?,
        Some(owner_id)
    );
    let second = service
        .provision_password_user(NewPasswordUser {
            username: "chargebee_postgres_second".into(),
            name: "Chargebee PostgreSQL Second".into(),
            email: Some("chargebee-postgres-second@example.test".into()),
            password: "chargebee postgres contract password".into(),
            role: "member".into(),
        })
        .await?;
    assert_eq!(
        store
            .set_user_customer_id(second.id, Some("chargebee_customer_owner".into()))
            .await,
        Err(ChargebeeStoreError::DuplicateCustomerId)
    );
    store.set_user_customer_id(owner_id, None).await?;
    assert!(store.user_customer_id(owner_id).await?.is_none());
    Ok(())
}

async fn assert_subscriptions_and_items(
    store: &PostgresChargebeeStore,
    pool: &PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let first = create_subscription(store, "account_resubscribe", "provider_first").await?;
    let second = create_subscription(store, "account_resubscribe", "provider_second").await?;
    assert_eq!(
        store
            .list_subscriptions_by_reference("account_resubscribe")
            .await?
            .len(),
        2
    );
    let duplicate = subscription("different_reference", "provider_first");
    assert_eq!(
        store.create_subscription(duplicate).await,
        Err(ChargebeeStoreError::DuplicateSubscriptionId)
    );

    let addon =
        ChargebeeSubscriptionItem::new(first.id, "price_addon", ChargebeeItemType::Addon, 1.0);
    let plan = ChargebeeSubscriptionItem::new(first.id, "price_plan", ChargebeeItemType::Plan, 3.0);
    store.create_subscription_item(addon.clone()).await?;
    store.create_subscription_item(plan.clone()).await?;
    assert_eq!(
        store.list_subscription_items(first.id).await?,
        [addon.clone(), plan.clone()]
    );
    assert_eq!(
        store.delete_subscription_items(first.id).await?,
        [addon, plan]
    );
    let replacement =
        ChargebeeSubscriptionItem::new(first.id, "price_replacement", ChargebeeItemType::Plan, 5.0);
    store.create_subscription_item(replacement.clone()).await?;
    assert_eq!(
        store.list_subscription_items(first.id).await?,
        [replacement]
    );

    store.delete_subscription(first.id).await?;
    assert_eq!(item_count(pool, first.id).await?, 0);
    assert_eq!(
        store
            .list_subscriptions_by_reference("account_resubscribe")
            .await?,
        [second]
    );
    Ok(())
}

async fn create_subscription(
    store: &PostgresChargebeeStore,
    reference: &str,
    provider_id: &str,
) -> Result<ChargebeeSubscription, ChargebeeStoreError> {
    store
        .create_subscription(subscription(reference, provider_id))
        .await
}

fn subscription(reference: &str, provider_id: &str) -> ChargebeeSubscription {
    let mut subscription = ChargebeeSubscription::future(reference, Utc::now());
    subscription.status = ChargebeeSubscriptionStatus::Active;
    subscription.chargebee_customer_id = Some("chargebee_customer_subscription".into());
    subscription.chargebee_subscription_id = Some(provider_id.into());
    subscription
}

async fn table_name(pool: &PgPool, table: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT to_regclass($1)::TEXT")
        .bind(table)
        .fetch_one(pool)
        .await
}

async fn migration_count(pool: &PgPool, id: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM lucid_auth_plugin_migrations \
         WHERE plugin_id = 'chargebee-postgres-contract' AND migration_id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
}

async fn organization_customer_column_count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_schema = current_schema() \
         AND table_name = 'lucid_auth_organizations' \
         AND column_name = 'chargebee_customer_id'",
    )
    .fetch_one(pool)
    .await
}

async fn item_count(pool: &PgPool, subscription_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM lucid_auth_chargebee_subscription_items WHERE subscription_id = $1",
    )
    .bind(subscription_id)
    .fetch_one(pool)
    .await
}
