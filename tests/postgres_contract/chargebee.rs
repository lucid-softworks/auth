use lucid_auth::{
    AuthPlugin, AuthService, ChargebeeItemType, ChargebeeStore, ChargebeeStoreError,
    ChargebeeSubscription, ChargebeeSubscriptionItem, ChargebeeSubscriptionStatus, NewPasswordUser,
    PluginDescriptor, PluginProvenance, PluginSchemaTable, PostgresChargebeeStore,
    chargebee_schema_tables, postgres::PostgresStore,
};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) struct SchemaPlugin;

#[async_trait::async_trait]
impl AuthPlugin for SchemaPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "chargebee-postgres-contract",
            display_name: "Chargebee PostgreSQL Contract",
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
        chargebee_schema_tables(true, false)
    }
}

pub(super) async fn assert_migration_and_persistence(
    service: &AuthService,
    store: &PostgresStore,
    pool: &PgPool,
    owner_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let chargebee = PostgresChargebeeStore::new(store.clone());
    assert_customer_linkage_and_uniqueness(service, &chargebee, owner_id).await?;
    assert_subscriptions_and_items(&chargebee, pool).await?;
    Ok(())
}

async fn assert_customer_linkage_and_uniqueness(
    service: &AuthService,
    store: &PostgresChargebeeStore,
    owner_id: &str,
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
        Some(owner_id.to_owned())
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
            .set_user_customer_id(&second.id, Some("chargebee_customer_owner".into()))
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
    let mut expected = vec![addon, plan];
    expected.sort_by_key(|item| item.id);
    assert_eq!(store.list_subscription_items(first.id).await?, expected);
    assert_eq!(store.delete_subscription_items(first.id).await?, expected);
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
    let mut subscription = ChargebeeSubscription::future(reference);
    subscription.status = ChargebeeSubscriptionStatus::Active;
    subscription.chargebee_customer_id = Some("chargebee_customer_subscription".into());
    subscription.chargebee_subscription_id = Some(provider_id.into());
    subscription
}

async fn item_count(pool: &PgPool, subscription_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM \"subscriptionItem\" WHERE \"subscriptionId\" = $1")
        .bind(subscription_id.to_string())
        .fetch_one(pool)
        .await
}
