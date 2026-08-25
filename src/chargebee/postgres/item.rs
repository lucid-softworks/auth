use super::{
    PostgresChargebeeStore, rows::ChargebeeSubscriptionItemRow, storage_error,
    subscriptions_disabled,
};
use crate::chargebee::{ChargebeeStoreError, ChargebeeSubscriptionItem};
use uuid::Uuid;

const TABLE: &str = "lucid_auth_chargebee_subscription_items";
const FIELDS: &str = "id, subscription_id, item_price_id, item_type, quantity, unit_price, amount";

pub(super) async fn create(
    store: &PostgresChargebeeStore,
    item: ChargebeeSubscriptionItem,
) -> Result<ChargebeeSubscriptionItem, ChargebeeStoreError> {
    require_enabled(store)?;
    sqlx::query_as::<_, ChargebeeSubscriptionItemRow>(&format!(
        "INSERT INTO {TABLE} ({FIELDS}) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING {FIELDS}"
    ))
    .bind(item.id)
    .bind(item.subscription_id)
    .bind(item.item_price_id)
    .bind(item.item_type.as_str())
    .bind(item.quantity)
    .bind(item.unit_price)
    .bind(item.amount)
    .fetch_one(store.pool())
    .await
    .map_err(storage_error)?
    .try_into()
}

pub(super) async fn list(
    store: &PostgresChargebeeStore,
    subscription_id: Uuid,
) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
    if !store.subscriptions_enabled {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, ChargebeeSubscriptionItemRow>(&format!(
        "SELECT {FIELDS} FROM {TABLE} WHERE subscription_id = $1 ORDER BY position"
    ))
    .bind(subscription_id)
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?
    .into_iter()
    .map(TryInto::try_into)
    .collect()
}

pub(super) async fn delete(
    store: &PostgresChargebeeStore,
    subscription_id: Uuid,
) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
    if !store.subscriptions_enabled {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, ChargebeeSubscriptionItemRow>(&format!(
        "WITH deleted AS (DELETE FROM {TABLE} WHERE subscription_id = $1 \
         RETURNING {FIELDS}, position) SELECT {FIELDS} FROM deleted ORDER BY position"
    ))
    .bind(subscription_id)
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?
    .into_iter()
    .map(TryInto::try_into)
    .collect()
}

fn require_enabled(store: &PostgresChargebeeStore) -> Result<(), ChargebeeStoreError> {
    if store.subscriptions_enabled {
        Ok(())
    } else {
        Err(subscriptions_disabled())
    }
}
