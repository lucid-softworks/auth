use super::{PostgresChargebeeStore, item_error, rows, schema_error, subscriptions_disabled};
use crate::{
    chargebee::{ChargebeeStoreError, ChargebeeSubscriptionItem},
    postgres::{PostgresModel, PostgresWrite},
};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, postgres::PgRow};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresChargebeeStore,
    item: ChargebeeSubscriptionItem,
) -> Result<ChargebeeSubscriptionItem, ChargebeeStoreError> {
    let model = store
        .model_if_present("subscriptionItem")?
        .ok_or_else(subscriptions_disabled)?;
    let mut query = insert_query(&model, rows::item_writes(&model, &item)?);
    query.push(" RETURNING ").push(model.all_projection());
    rows::decode_item(
        &model,
        &query
            .build()
            .fetch_one(store.pool())
            .await
            .map_err(item_error)?,
    )
}
pub(super) async fn list(
    store: &PostgresChargebeeStore,
    id: Uuid,
) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
    let Some(model) = store.model_if_present("subscriptionItem")? else {
        return Ok(Vec::new());
    };
    let mut query = filter_query(&model, id, false)?;
    let rows = query
        .build()
        .fetch_all(store.pool())
        .await
        .map_err(item_error)?;
    decode_items(&model, &rows)
}
pub(super) async fn delete(
    store: &PostgresChargebeeStore,
    id: Uuid,
) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
    let Some(model) = store.model_if_present("subscriptionItem")? else {
        return Ok(Vec::new());
    };
    let mut query = filter_query(&model, id, true)?;
    let rows = query
        .build()
        .fetch_all(store.pool())
        .await
        .map_err(item_error)?;
    decode_items(&model, &rows)
}

fn decode_items(
    model: &PostgresModel<'_>,
    rows: &[PgRow],
) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
    let mut items = rows
        .iter()
        .map(|row| rows::decode_item(model, row))
        .collect::<Result<Vec<_>, _>>()?;
    items.sort_by_key(|item| item.id);
    Ok(items)
}
fn filter_query(
    model: &PostgresModel<'_>,
    id: Uuid,
    delete: bool,
) -> Result<QueryBuilder<'static, Postgres>, ChargebeeStoreError> {
    let mut query = QueryBuilder::new(if delete { "DELETE FROM " } else { "SELECT " });
    if delete {
        query.push(model.quoted_table());
    } else {
        query
            .push(model.all_projection())
            .push(" FROM ")
            .push(model.quoted_table());
    }
    query
        .push(" WHERE ")
        .push(
            model
                .quoted_column("subscriptionId")
                .map_err(schema_error)?,
        )
        .push(" = ");
    model
        .encode("subscriptionId", json!(id.to_string()))
        .map_err(schema_error)?
        .push_bind(&mut query);
    if delete {
        query.push(" RETURNING ").push(model.all_projection());
    } else {
        query.push(" ORDER BY \"id\"");
    }
    Ok(query)
}
fn insert_query(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("INSERT INTO ");
    query.push(model.quoted_table()).push(" (");
    for (i, w) in writes.iter().enumerate() {
        if i > 0 {
            query.push(", ");
        }
        query.push(w.quoted_column());
    }
    query.push(") VALUES (");
    for (i, w) in writes.into_iter().enumerate() {
        if i > 0 {
            query.push(", ");
        }
        w.push_bind(&mut query);
    }
    query.push(")");
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn item_queries_use_exact_fields_and_never_position() {
        let store = super::super::test_support::store();
        let model = store.model("subscriptionItem").unwrap();
        let list = filter_query(&model, Uuid::nil(), false).unwrap();
        assert!(
            list.sql()
                .contains("FROM \"chargebee\"\"subscriptionItems\"")
        );
        assert!(list.sql().contains("\"physical subscriptionId\" = $1"));
        assert!(!list.sql().contains("position"));
    }
}
