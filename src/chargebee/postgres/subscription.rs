use super::{
    PostgresChargebeeStore, rows::ChargebeeSubscriptionRow, storage_error, subscriptions_disabled,
};
use crate::chargebee::{ChargebeeStoreError, ChargebeeSubscription, ChargebeeSubscriptionPatch};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

const TABLE: &str = "lucid_auth_chargebee_subscriptions";
const FIELDS: &str = "id, reference_id, chargebee_customer_id, chargebee_subscription_id, \
    status, period_start, period_end, trial_start, trial_end, canceled_at, seats, metadata, \
    created_at, updated_at";

pub(super) async fn create(
    store: &PostgresChargebeeStore,
    subscription: ChargebeeSubscription,
) -> Result<ChargebeeSubscription, ChargebeeStoreError> {
    require_enabled(store)?;
    let query = format!(
        "INSERT INTO {TABLE} ({FIELDS}) VALUES \
         ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         RETURNING {FIELDS}"
    );
    sqlx::query_as::<_, ChargebeeSubscriptionRow>(&query)
        .bind(subscription.id)
        .bind(subscription.reference_id)
        .bind(subscription.chargebee_customer_id)
        .bind(subscription.chargebee_subscription_id)
        .bind(subscription.status.as_str())
        .bind(subscription.period_start)
        .bind(subscription.period_end)
        .bind(subscription.trial_start)
        .bind(subscription.trial_end)
        .bind(subscription.canceled_at)
        .bind(subscription.seats)
        .bind(subscription.metadata)
        .bind(subscription.created_at)
        .bind(subscription.updated_at)
        .fetch_one(store.pool())
        .await
        .map_err(storage_error)?
        .try_into()
}

pub(super) async fn find(
    store: &PostgresChargebeeStore,
    id: Uuid,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    if !store.subscriptions_enabled {
        return Ok(None);
    }
    optional(
        sqlx::query_as::<_, ChargebeeSubscriptionRow>(&format!(
            "SELECT {FIELDS} FROM {TABLE} WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn find_by_chargebee_id(
    store: &PostgresChargebeeStore,
    chargebee_id: &str,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    if !store.subscriptions_enabled {
        return Ok(None);
    }
    optional(
        sqlx::query_as::<_, ChargebeeSubscriptionRow>(&format!(
            "SELECT {FIELDS} FROM {TABLE} WHERE chargebee_subscription_id = $1 LIMIT 1"
        ))
        .bind(chargebee_id)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn list_by_reference(
    store: &PostgresChargebeeStore,
    reference_id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    list_where(store, "reference_id", reference_id).await
}

pub(super) async fn list_by_customer(
    store: &PostgresChargebeeStore,
    customer_id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    list_where(store, "chargebee_customer_id", customer_id).await
}

async fn list_where(
    store: &PostgresChargebeeStore,
    column: &str,
    value: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    if !store.subscriptions_enabled {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, ChargebeeSubscriptionRow>(&format!(
        "SELECT {FIELDS} FROM {TABLE} WHERE {column} = $1 ORDER BY created_at, id"
    ))
    .bind(value)
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?
    .into_iter()
    .map(TryInto::try_into)
    .collect()
}

pub(super) async fn update(
    store: &PostgresChargebeeStore,
    id: Uuid,
    patch: ChargebeeSubscriptionPatch,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    require_enabled(store)?;
    let Some(mut query) = update_query(id, patch) else {
        return find(store, id).await;
    };
    optional(
        query
            .build_query_as::<ChargebeeSubscriptionRow>()
            .fetch_optional(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

pub(super) async fn delete(
    store: &PostgresChargebeeStore,
    id: Uuid,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    if !store.subscriptions_enabled {
        return Ok(None);
    }
    optional(
        sqlx::query_as::<_, ChargebeeSubscriptionRow>(&format!(
            "DELETE FROM {TABLE} WHERE id = $1 RETURNING {FIELDS}"
        ))
        .bind(id)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn delete_by_reference(
    store: &PostgresChargebeeStore,
    reference_id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    delete_where(store, "reference_id", reference_id).await
}

pub(super) async fn delete_by_customer(
    store: &PostgresChargebeeStore,
    customer_id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    delete_where(store, "chargebee_customer_id", customer_id).await
}

async fn delete_where(
    store: &PostgresChargebeeStore,
    column: &str,
    value: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    if !store.subscriptions_enabled {
        return Ok(Vec::new());
    }
    let query = format!(
        "WITH deleted AS (DELETE FROM {TABLE} WHERE {column} = $1 RETURNING {FIELDS}) \
         SELECT {FIELDS} FROM deleted ORDER BY created_at, id"
    );
    sqlx::query_as::<_, ChargebeeSubscriptionRow>(&query)
        .bind(value)
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
}

fn update_query(
    id: Uuid,
    patch: ChargebeeSubscriptionPatch,
) -> Option<QueryBuilder<'static, Postgres>> {
    let mut query = QueryBuilder::new(format!("UPDATE {TABLE} SET "));
    let mut assignments = query.separated(", ");
    let mut changed = false;

    macro_rules! assign {
        ($column:literal, $value:expr) => {
            if let Some(value) = $value {
                changed = true;
                assignments
                    .push(concat!($column, " = "))
                    .push_bind_unseparated(value);
            }
        };
    }

    assign!("reference_id", patch.reference_id);
    assign!("chargebee_customer_id", patch.chargebee_customer_id);
    assign!("chargebee_subscription_id", patch.chargebee_subscription_id);
    assign!("status", patch.status.map(|status| status.to_string()));
    assign!("period_start", patch.period_start);
    assign!("period_end", patch.period_end);
    assign!("trial_start", patch.trial_start);
    assign!("trial_end", patch.trial_end);
    assign!("canceled_at", patch.canceled_at);
    assign!("seats", patch.seats);
    assign!("metadata", patch.metadata);
    assign!("updated_at", patch.updated_at);
    if !changed {
        return None;
    }
    query
        .push(" WHERE id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(FIELDS);
    Some(query)
}

fn require_enabled(store: &PostgresChargebeeStore) -> Result<(), ChargebeeStoreError> {
    if store.subscriptions_enabled {
        Ok(())
    } else {
        Err(subscriptions_disabled())
    }
}

fn optional(
    row: Option<ChargebeeSubscriptionRow>,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    row.map(TryInto::try_into).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn patch_query_distinguishes_omission_from_null() {
        let id = Uuid::new_v4();
        let query = update_query(
            id,
            ChargebeeSubscriptionPatch {
                chargebee_customer_id: Some(None),
                status: Some(crate::chargebee::ChargebeeSubscriptionStatus::Active),
                updated_at: Some(Utc::now()),
                ..ChargebeeSubscriptionPatch::default()
            },
        )
        .unwrap()
        .sql()
        .to_owned();
        assert!(query.contains("chargebee_customer_id = $1"));
        assert!(query.contains("status = $2"));
        assert!(!query.contains("metadata ="));
        assert!(query.contains("WHERE id = $4"));
    }
}
