use super::{PostgresCreemStore, rows::SubscriptionRow, storage_error};
use crate::creem::{
    CreemStoreError, CreemSubscription, CreemSubscriptionPatch, schema::ResolvedModel,
};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresCreemStore,
    subscription: CreemSubscription,
) -> Result<CreemSubscription, CreemStoreError> {
    let model = subscription_model(store)?;
    let query = insert_query(model);
    sqlx::query_as::<_, SubscriptionRow>(&query)
        .bind(subscription.id)
        .bind(subscription.product_id)
        .bind(subscription.reference_id)
        .bind(subscription.creem_customer_id)
        .bind(subscription.creem_subscription_id)
        .bind(subscription.creem_order_id)
        .bind(subscription.status)
        .bind(subscription.period_start)
        .bind(subscription.period_end)
        .bind(subscription.cancel_at_period_end)
        .fetch_one(store.pool())
        .await
        .map(Into::into)
        .map_err(storage_error)
}

pub(super) async fn find_by_creem_id(
    store: &PostgresCreemStore,
    creem_subscription_id: &str,
) -> Result<Option<CreemSubscription>, CreemStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(None);
    };
    let query = find_by_creem_id_query(model);
    optional_row(
        sqlx::query_as::<_, SubscriptionRow>(&query)
            .bind(creem_subscription_id)
            .fetch_optional(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

pub(super) async fn list_by_reference(
    store: &PostgresCreemStore,
    reference_id: &str,
) -> Result<Vec<CreemSubscription>, CreemStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(Vec::new());
    };
    let query = list_query(model, "referenceId");
    rows(
        sqlx::query_as::<_, SubscriptionRow>(&query)
            .bind(reference_id)
            .fetch_all(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

pub(super) async fn list_by_customer(
    store: &PostgresCreemStore,
    creem_customer_id: &str,
) -> Result<Vec<CreemSubscription>, CreemStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(Vec::new());
    };
    let query = list_query(model, "creemCustomerId");
    rows(
        sqlx::query_as::<_, SubscriptionRow>(&query)
            .bind(creem_customer_id)
            .fetch_all(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

pub(super) async fn update(
    store: &PostgresCreemStore,
    id: Uuid,
    patch: CreemSubscriptionPatch,
) -> Result<Option<CreemSubscription>, CreemStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(None);
    };
    let Some(mut query) = update_query(model, id, patch) else {
        return find_by_id(store, id).await;
    };
    optional_row(
        query
            .build_query_as::<SubscriptionRow>()
            .fetch_optional(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

async fn find_by_id(
    store: &PostgresCreemStore,
    id: Uuid,
) -> Result<Option<CreemSubscription>, CreemStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(None);
    };
    let query = format!(
        "SELECT {} FROM {} WHERE \"id\" = $1",
        model.projection(),
        model.table()
    );
    optional_row(
        sqlx::query_as::<_, SubscriptionRow>(&query)
            .bind(id)
            .fetch_optional(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

fn subscription_model(store: &PostgresCreemStore) -> Result<&ResolvedModel, CreemStoreError> {
    store.schema.subscription().ok_or_else(|| {
        CreemStoreError::Unavailable("Creem subscription persistence is disabled".into())
    })
}

fn insert_query(model: &ResolvedModel) -> String {
    format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING {}",
        model.table(),
        columns(model),
        placeholders(10),
        model.projection()
    )
}

fn columns(model: &ResolvedModel) -> String {
    [
        "id",
        "productId",
        "referenceId",
        "creemCustomerId",
        "creemSubscriptionId",
        "creemOrderId",
        "status",
        "periodStart",
        "periodEnd",
        "cancelAtPeriodEnd",
    ]
    .map(|field| model.column(field))
    .join(", ")
}

fn placeholders(count: usize) -> String {
    (1..=count)
        .map(|position| format!("${position}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn find_by_creem_id_query(model: &ResolvedModel) -> String {
    format!(
        "SELECT {} FROM {} WHERE {} = $1 LIMIT 1",
        model.projection(),
        model.table(),
        model.column("creemSubscriptionId")
    )
}

fn list_query(model: &ResolvedModel, logical_field: &str) -> String {
    format!(
        "SELECT {} FROM {} WHERE {} = $1",
        model.projection(),
        model.table(),
        model.column(logical_field)
    )
}

fn update_query(
    model: &ResolvedModel,
    id: Uuid,
    patch: CreemSubscriptionPatch,
) -> Option<QueryBuilder<'static, Postgres>> {
    let mut query = QueryBuilder::new(format!("UPDATE {} SET ", model.table()));
    let mut assignments = query.separated(", ");
    let mut changed = false;

    macro_rules! assign {
        ($logical:literal, $value:expr) => {
            if let Some(value) = $value {
                changed = true;
                assignments
                    .push(format!("{} = ", model.column($logical)))
                    .push_bind_unseparated(value);
            }
        };
    }

    assign!("status", patch.status);
    assign!("productId", patch.product_id);
    assign!("referenceId", patch.reference_id);
    assign!("creemCustomerId", patch.creem_customer_id);
    assign!("creemSubscriptionId", patch.creem_subscription_id);
    assign!("creemOrderId", patch.creem_order_id);
    assign!("periodStart", patch.period_start);
    assign!("periodEnd", patch.period_end);
    if !changed {
        return None;
    }
    query
        .push(" WHERE \"id\" = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(model.projection());
    Some(query)
}

fn optional_row(
    row: Option<SubscriptionRow>,
) -> Result<Option<CreemSubscription>, CreemStoreError> {
    Ok(row.map(Into::into))
}

fn rows(rows: Vec<SubscriptionRow>) -> Result<Vec<CreemSubscription>, CreemStoreError> {
    Ok(rows.into_iter().map(Into::into).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creem::{CreemModelSchema, CreemSchema, schema::ResolvedCreemSchema};
    use std::collections::BTreeMap;

    fn model(schema: &CreemSchema) -> ResolvedModel {
        ResolvedCreemSchema::new(schema, true)
            .unwrap()
            .subscription()
            .unwrap()
            .clone()
    }

    #[test]
    fn every_query_uses_remapped_identifiers_without_ordering() {
        let mut schema = CreemSchema::default();
        schema.insert_model(
            "creem_subscription",
            CreemModelSchema {
                model_name: Some("billing rows".into()),
                fields: BTreeMap::from([
                    ("referenceId".into(), "owner key".into()),
                    ("creemSubscriptionId".into(), "provider key".into()),
                ]),
            },
        );
        let model = model(&schema);
        let find = find_by_creem_id_query(&model);
        let list = list_query(&model, "referenceId");
        assert!(find.contains("FROM \"billing rows\""));
        assert!(find.contains("WHERE \"provider key\" = $1 LIMIT 1"));
        assert!(list.contains("WHERE \"owner key\" = $1"));
        assert!(!find.contains("ORDER BY"));
        assert!(!list.contains("ORDER BY"));
        assert!(columns(&model).contains("\"owner key\""));
    }

    #[test]
    fn subscription_event_patch_sql_leaves_checkout_owned_fields_untouched() {
        let model = model(&CreemSchema::default());
        let query = update_query(
            &model,
            Uuid::nil(),
            CreemSubscriptionPatch {
                status: Some("active".into()),
                period_end: Some(None),
                ..CreemSubscriptionPatch::default()
            },
        )
        .unwrap();
        let sql = query.sql();
        assert!(sql.contains("\"status\" = $1"));
        assert!(sql.contains("\"period_end\" = $2"));
        assert!(!sql.contains("\"product_id\" ="));
        assert!(!sql.contains("\"reference_id\" ="));
        assert!(!sql.contains("\"creem_order_id\" ="));
        assert!(!sql.contains("\"cancel_at_period_end\" ="));
    }

    #[test]
    fn checkout_patch_sql_updates_the_complete_upsert_shape() {
        let model = model(&CreemSchema::default());
        let query = update_query(
            &model,
            Uuid::nil(),
            CreemSubscriptionPatch {
                product_id: Some("product".into()),
                reference_id: Some("owner".into()),
                creem_order_id: Some(Some("order".into())),
                ..CreemSubscriptionPatch::default()
            },
        )
        .unwrap();
        let sql = query.sql();
        assert!(sql.contains("\"product_id\" = $1"));
        assert!(sql.contains("\"reference_id\" = $2"));
        assert!(sql.contains("\"creem_order_id\" = $3"));
        assert!(!sql.contains("\"cancel_at_period_end\" ="));
    }

    #[test]
    fn empty_patch_avoids_invalid_update_sql() {
        let model = model(&CreemSchema::default());
        assert!(update_query(&model, Uuid::nil(), CreemSubscriptionPatch::default()).is_none());
    }
}
