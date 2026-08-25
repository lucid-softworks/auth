use super::{PostgresStripeStore, rows::SubscriptionRow, storage_error};
use crate::stripe::{StripeStoreError, Subscription, SubscriptionPatch};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresStripeStore,
    subscription: Subscription,
) -> Result<Subscription, StripeStoreError> {
    let model = subscription_model(store)?;
    let columns = subscription_columns(model);
    let query = format!(
        "INSERT INTO {} ({columns}) VALUES ({}) RETURNING {}",
        model.table(),
        placeholders(19),
        model.projection()
    );
    let row = sqlx::query_as::<_, SubscriptionRow>(&query)
        .bind(subscription.id)
        .bind(subscription.plan)
        .bind(subscription.reference_id)
        .bind(subscription.stripe_customer_id)
        .bind(subscription.stripe_subscription_id)
        .bind(subscription.status.as_str())
        .bind(subscription.period_start)
        .bind(subscription.period_end)
        .bind(subscription.trial_start)
        .bind(subscription.trial_end)
        .bind(subscription.cancel_at_period_end)
        .bind(subscription.cancel_at)
        .bind(subscription.canceled_at)
        .bind(subscription.ended_at)
        .bind(subscription.seats)
        .bind(subscription.billing_interval.map(|value| value.as_str()))
        .bind(subscription.stripe_schedule_id)
        .bind(subscription.created_at)
        .bind(subscription.updated_at)
        .fetch_one(store.pool())
        .await
        .map_err(storage_error)?;
    row.try_into()
}

pub(super) async fn find(
    store: &PostgresStripeStore,
    id: Uuid,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(None);
    };
    let query = format!(
        "SELECT {} FROM {} WHERE id = $1",
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

pub(super) async fn find_by_stripe_id(
    store: &PostgresStripeStore,
    stripe_subscription_id: &str,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(None);
    };
    let query = format!(
        "SELECT {} FROM {} WHERE {} = $1 ORDER BY {}, id LIMIT 1",
        model.projection(),
        model.table(),
        model.column("stripeSubscriptionId"),
        model.column("createdAt")
    );
    optional_row(
        sqlx::query_as::<_, SubscriptionRow>(&query)
            .bind(stripe_subscription_id)
            .fetch_optional(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

pub(super) async fn list(
    store: &PostgresStripeStore,
    reference_id: &str,
) -> Result<Vec<Subscription>, StripeStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(Vec::new());
    };
    let query = list_query(model);
    sqlx::query_as::<_, SubscriptionRow>(&query)
        .bind(reference_id)
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
}

pub(super) async fn list_by_customer(
    store: &PostgresStripeStore,
    stripe_customer_id: &str,
) -> Result<Vec<Subscription>, StripeStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(Vec::new());
    };
    let query = format!(
        "SELECT {} FROM {} WHERE {} = $1 ORDER BY {}, id",
        model.projection(),
        model.table(),
        model.column("stripeCustomerId"),
        model.column("createdAt")
    );
    sqlx::query_as::<_, SubscriptionRow>(&query)
        .bind(stripe_customer_id)
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
}

pub(super) async fn find_active_by_customer(
    store: &PostgresStripeStore,
    stripe_customer_id: &str,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(None);
    };
    let query = format!(
        "SELECT {} FROM {} WHERE {} = $1 AND {} IN ('active', 'trialing') \
         ORDER BY {}, id LIMIT 1",
        model.projection(),
        model.table(),
        model.column("stripeCustomerId"),
        model.column("status"),
        model.column("createdAt")
    );
    optional_row(
        sqlx::query_as::<_, SubscriptionRow>(&query)
            .bind(stripe_customer_id)
            .fetch_optional(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

pub(super) async fn update(
    store: &PostgresStripeStore,
    id: Uuid,
    patch: SubscriptionPatch,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(None);
    };
    let Some(mut query) = update_query(model, id, patch) else {
        return find(store, id).await;
    };
    let row = query
        .build_query_as::<SubscriptionRow>()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?;
    optional_row(row)
}

pub(super) async fn delete(
    store: &PostgresStripeStore,
    id: Uuid,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.schema.subscription() else {
        return Ok(None);
    };
    let query = format!(
        "DELETE FROM {} WHERE id = $1 RETURNING {}",
        model.table(),
        model.projection()
    );
    optional_row(
        sqlx::query_as::<_, SubscriptionRow>(&query)
            .bind(id)
            .fetch_optional(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

fn subscription_model(
    store: &PostgresStripeStore,
) -> Result<&crate::stripe::schema::ResolvedModel, StripeStoreError> {
    store.schema.subscription().ok_or_else(|| {
        StripeStoreError::Unavailable("Stripe subscriptions are disabled".to_owned())
    })
}

fn subscription_columns(model: &crate::stripe::schema::ResolvedModel) -> String {
    [
        "id",
        "plan",
        "referenceId",
        "stripeCustomerId",
        "stripeSubscriptionId",
        "status",
        "periodStart",
        "periodEnd",
        "trialStart",
        "trialEnd",
        "cancelAtPeriodEnd",
        "cancelAt",
        "canceledAt",
        "endedAt",
        "seats",
        "billingInterval",
        "stripeScheduleId",
        "createdAt",
        "updatedAt",
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

fn list_query(model: &crate::stripe::schema::ResolvedModel) -> String {
    format!(
        "SELECT {} FROM {} WHERE {} = $1 ORDER BY {}, id",
        model.projection(),
        model.table(),
        model.column("referenceId"),
        model.column("createdAt")
    )
}

fn update_query(
    model: &crate::stripe::schema::ResolvedModel,
    id: Uuid,
    patch: SubscriptionPatch,
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

    assign!("plan", patch.plan);
    assign!("stripeCustomerId", patch.stripe_customer_id);
    assign!("stripeSubscriptionId", patch.stripe_subscription_id);
    assign!("status", patch.status.map(|value| value.as_str()));
    assign!("periodStart", patch.period_start);
    assign!("periodEnd", patch.period_end);
    assign!("trialStart", patch.trial_start);
    assign!("trialEnd", patch.trial_end);
    assign!("cancelAtPeriodEnd", patch.cancel_at_period_end);
    assign!("cancelAt", patch.cancel_at);
    assign!("canceledAt", patch.canceled_at);
    assign!("endedAt", patch.ended_at);
    assign!("seats", patch.seats);
    assign!(
        "billingInterval",
        patch
            .billing_interval
            .map(|value| value.map(|interval| interval.as_str()))
    );
    assign!("stripeScheduleId", patch.stripe_schedule_id);
    assign!("updatedAt", patch.updated_at);
    if !changed {
        return None;
    }
    query
        .push(" WHERE id = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(model.projection());
    Some(query)
}

fn optional_row(row: Option<SubscriptionRow>) -> Result<Option<Subscription>, StripeStoreError> {
    row.map(TryInto::try_into).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::{StripeModelSchema, StripeSchema, schema::ResolvedStripeSchema};
    use std::collections::BTreeMap;

    fn model(schema: &StripeSchema) -> crate::stripe::schema::ResolvedModel {
        ResolvedStripeSchema::new(schema, true, false)
            .unwrap()
            .subscription()
            .unwrap()
            .clone()
    }

    #[test]
    fn insert_and_list_queries_apply_every_subscription_remap() {
        let model = model(&StripeSchema {
            subscription: StripeModelSchema {
                model_name: Some("billing rows".into()),
                fields: BTreeMap::from([
                    ("referenceId".into(), "owner \"id\"".into()),
                    ("createdAt".into(), "inserted at".into()),
                ]),
            },
            ..StripeSchema::default()
        });

        assert!(subscription_columns(&model).contains("\"owner \"\"id\"\"\""));
        let query = list_query(&model);
        assert!(query.contains("FROM \"billing rows\""));
        assert!(query.contains("WHERE \"owner \"\"id\"\"\" = $1"));
        assert!(query.ends_with("ORDER BY \"inserted at\", id"));
        assert_eq!(placeholders(3), "$1, $2, $3");
    }

    #[test]
    fn patch_query_distinguishes_omission_from_null() {
        let model = model(&StripeSchema::default());
        let query = update_query(
            &model,
            Uuid::nil(),
            SubscriptionPatch {
                plan: Some("pro".into()),
                cancel_at: Some(None),
                stripe_schedule_id: Some(None),
                ..SubscriptionPatch::default()
            },
        )
        .unwrap();
        let sql = query.sql();
        assert!(sql.contains("\"plan\" = $1"), "{sql}");
        assert!(sql.contains("\"cancel_at\" = $2"), "{sql}");
        assert!(sql.contains("\"stripe_schedule_id\" = $3"), "{sql}");
        assert!(sql.contains("WHERE id = $4"), "{sql}");
        assert!(!sql.contains("\"period_end\" ="));
    }

    #[test]
    fn empty_patch_does_not_emit_invalid_update_sql() {
        let model = model(&StripeSchema::default());
        assert!(update_query(&model, Uuid::nil(), SubscriptionPatch::default()).is_none());
    }
}
