use super::{PostgresChargebeeStore, customer_error, schema_error};
use crate::{chargebee::ChargebeeStoreError, postgres::PostgresModel};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

const FIELD: &str = "chargebeeCustomerId";

pub(super) async fn user_customer_id(
    store: &PostgresChargebeeStore,
    id: &str,
) -> Result<Option<String>, ChargebeeStoreError> {
    customer_id(store, "user", json!(id)).await
}
pub(super) async fn set_user_customer_id(
    store: &PostgresChargebeeStore,
    id: &str,
    value: Option<String>,
) -> Result<(), ChargebeeStoreError> {
    set_customer_id(store, "user", json!(id), value).await
}
pub(super) async fn user_id_by_customer(
    store: &PostgresChargebeeStore,
    value: &str,
) -> Result<Option<String>, ChargebeeStoreError> {
    string_id_by_customer(store, "user", value).await
}
pub(super) async fn organization_customer_id(
    store: &PostgresChargebeeStore,
    id: Uuid,
) -> Result<Option<String>, ChargebeeStoreError> {
    customer_id(store, "organization", json!(id.to_string())).await
}
pub(super) async fn set_organization_customer_id(
    store: &PostgresChargebeeStore,
    id: Uuid,
    value: Option<String>,
) -> Result<(), ChargebeeStoreError> {
    set_customer_id(store, "organization", json!(id.to_string()), value).await
}
pub(super) async fn organization_id_by_customer(
    store: &PostgresChargebeeStore,
    value: &str,
) -> Result<Option<Uuid>, ChargebeeStoreError> {
    uuid_id_by_customer(store, "organization", value).await
}

async fn customer_id(
    store: &PostgresChargebeeStore,
    logical: &str,
    id: Value,
) -> Result<Option<String>, ChargebeeStoreError> {
    let Some(model) = customer_model(store, logical)? else {
        return Ok(None);
    };
    let mut query = select_query(&model, id)?;
    query
        .build_query_scalar()
        .fetch_optional(store.pool())
        .await
        .map(|value| value.flatten())
        .map_err(customer_error)
}

async fn set_customer_id(
    store: &PostgresChargebeeStore,
    logical: &str,
    id: Value,
    value: Option<String>,
) -> Result<(), ChargebeeStoreError> {
    let Some(model) = customer_model(store, logical)? else {
        return Ok(());
    };
    let mut query = update_query(&model, id, value)?;
    query
        .build()
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(customer_error)
}

async fn uuid_id_by_customer(
    store: &PostgresChargebeeStore,
    logical: &str,
    value: &str,
) -> Result<Option<Uuid>, ChargebeeStoreError> {
    let Some(model) = customer_model(store, logical)? else {
        return Ok(None);
    };
    let mut query = reverse_query(&model, value, false)?;
    query
        .build_query_scalar()
        .fetch_optional(store.pool())
        .await
        .map_err(customer_error)
}

async fn string_id_by_customer(
    store: &PostgresChargebeeStore,
    logical: &str,
    value: &str,
) -> Result<Option<String>, ChargebeeStoreError> {
    let Some(model) = customer_model(store, logical)? else {
        return Ok(None);
    };
    let mut query = reverse_query(&model, value, true)?;
    query
        .build_query_scalar()
        .fetch_optional(store.pool())
        .await
        .map_err(customer_error)
}

fn customer_model<'a>(
    store: &'a PostgresChargebeeStore,
    logical: &str,
) -> Result<Option<PostgresModel<'a>>, ChargebeeStoreError> {
    Ok(store
        .model_if_present(logical)?
        .filter(|model| model.has_field(FIELD)))
}
fn select_query(
    model: &PostgresModel<'_>,
    id: Value,
) -> Result<QueryBuilder<'static, Postgres>, ChargebeeStoreError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.quoted_column(FIELD).map_err(schema_error)?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ");
    model
        .encode("id", id)
        .map_err(schema_error)?
        .push_bind(&mut query);
    Ok(query)
}
fn update_query(
    model: &PostgresModel<'_>,
    id: Value,
    value: Option<String>,
) -> Result<QueryBuilder<'static, Postgres>, ChargebeeStoreError> {
    let mut query = QueryBuilder::new("UPDATE ");
    query
        .push(model.quoted_table())
        .push(" SET ")
        .push(model.quoted_column(FIELD).map_err(schema_error)?)
        .push(" = ");
    model
        .encode(FIELD, value.map_or(Value::Null, Value::String))
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(" WHERE \"id\" = ");
    model
        .encode("id", id)
        .map_err(schema_error)?
        .push_bind(&mut query);
    Ok(query)
}
fn reverse_query(
    model: &PostgresModel<'_>,
    value: &str,
    text_id: bool,
) -> Result<QueryBuilder<'static, Postgres>, ChargebeeStoreError> {
    let mut query = QueryBuilder::new(if text_id {
        "SELECT \"id\"::TEXT FROM "
    } else {
        "SELECT \"id\" FROM "
    });
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(FIELD).map_err(schema_error)?)
        .push(" = ");
    model
        .encode(FIELD, json!(value))
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(" ORDER BY \"id\" LIMIT 1");
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn customer_queries_use_physical_columns_without_json() {
        let store = super::super::test_support::store();
        let organization = store.model("organization").unwrap();
        let select = select_query(&organization, json!(Uuid::nil().to_string())).unwrap();
        assert!(select.sql().contains("FROM \"chargebee\"\"organizations\""));
        assert!(
            select
                .sql()
                .contains("SELECT \"physical chargebeeCustomerId\"")
        );
        assert!(!select.sql().contains("additional_fields"));
        let update = update_query(
            &organization,
            json!(Uuid::nil().to_string()),
            Some("customer_secret".into()),
        )
        .unwrap();
        assert!(!update.sql().contains("customer_secret"));
    }
}
