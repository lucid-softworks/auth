use super::{PostgresStripeStore, storage_error};
use crate::{postgres::PostgresModel, stripe::StripeStoreError};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};

const CUSTOMER_FIELD: &str = "stripeCustomerId";

pub(super) async fn user_customer_id(
    store: &PostgresStripeStore,
    user_id: &str,
) -> Result<Option<String>, StripeStoreError> {
    let model = store.model("user")?;
    scalar(store, customer_query(&model, json!(user_id))?).await
}

pub(super) async fn set_user_customer_id(
    store: &PostgresStripeStore,
    user_id: &str,
    customer_id: Option<String>,
) -> Result<(), StripeStoreError> {
    let model = store.model("user")?;
    execute(
        store,
        set_customer_query(&model, json!(user_id), customer_id)?,
    )
    .await
}

pub(super) async fn user_id_by_customer(
    store: &PostgresStripeStore,
    customer_id: &str,
) -> Result<Option<String>, StripeStoreError> {
    let model = store.model("user")?;
    string_id_by_customer(store, by_customer_query(&model, customer_id, true)?).await
}

pub(super) async fn organization_customer_id(
    store: &PostgresStripeStore,
    organization_id: &str,
) -> Result<Option<String>, StripeStoreError> {
    let Some(model) = customer_model(store, "organization")? else {
        return Ok(None);
    };
    scalar(store, customer_query(&model, json!(organization_id))?).await
}

pub(super) async fn set_organization_customer_id(
    store: &PostgresStripeStore,
    organization_id: String,
    customer_id: Option<String>,
) -> Result<(), StripeStoreError> {
    let Some(model) = customer_model(store, "organization")? else {
        return Ok(());
    };
    execute(
        store,
        set_customer_query(&model, json!(organization_id), customer_id)?,
    )
    .await
}

pub(super) async fn organization_id_by_customer(
    store: &PostgresStripeStore,
    customer_id: &str,
) -> Result<Option<String>, StripeStoreError> {
    let Some(model) = customer_model(store, "organization")? else {
        return Ok(None);
    };
    string_id_by_customer(store, by_customer_query(&model, customer_id, false)?).await
}

fn customer_query(
    model: &PostgresModel<'_>,
    id: Value,
) -> Result<QueryBuilder<'static, Postgres>, StripeStoreError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.quoted_column(CUSTOMER_FIELD).map_err(schema_error)?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ");
    model
        .encode("id", id)
        .map_err(schema_error)?
        .push_bind(&mut query);
    Ok(query)
}

fn set_customer_query(
    model: &PostgresModel<'_>,
    id: Value,
    customer_id: Option<String>,
) -> Result<QueryBuilder<'static, Postgres>, StripeStoreError> {
    let mut query = QueryBuilder::new("UPDATE ");
    query
        .push(model.quoted_table())
        .push(" SET ")
        .push(model.quoted_column(CUSTOMER_FIELD).map_err(schema_error)?)
        .push(" = ");
    model
        .encode(
            CUSTOMER_FIELD,
            customer_id.map_or(Value::Null, Value::String),
        )
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(" WHERE \"id\" = ");
    model
        .encode("id", id)
        .map_err(schema_error)?
        .push_bind(&mut query);
    Ok(query)
}

fn by_customer_query(
    model: &PostgresModel<'_>,
    customer_id: &str,
    text_id: bool,
) -> Result<QueryBuilder<'static, Postgres>, StripeStoreError> {
    let mut query = QueryBuilder::new(if text_id {
        "SELECT \"id\"::TEXT FROM "
    } else {
        "SELECT \"id\" FROM "
    });
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(CUSTOMER_FIELD).map_err(schema_error)?)
        .push(" = ");
    model
        .encode(CUSTOMER_FIELD, json!(customer_id))
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(" ORDER BY \"id\" LIMIT 1");
    Ok(query)
}

fn customer_model<'a>(
    store: &'a PostgresStripeStore,
    logical: &str,
) -> Result<Option<PostgresModel<'a>>, StripeStoreError> {
    Ok(store
        .model_if_present(logical)?
        .filter(|model| model.has_field(CUSTOMER_FIELD)))
}

async fn scalar(
    store: &PostgresStripeStore,
    mut query: QueryBuilder<'static, Postgres>,
) -> Result<Option<String>, StripeStoreError> {
    query
        .build_query_scalar()
        .fetch_optional(store.pool())
        .await
        .map(|value| value.flatten())
        .map_err(storage_error)
}

async fn string_id_by_customer(
    store: &PostgresStripeStore,
    mut query: QueryBuilder<'static, Postgres>,
) -> Result<Option<String>, StripeStoreError> {
    query
        .build_query_scalar()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)
}

async fn execute(
    store: &PostgresStripeStore,
    mut query: QueryBuilder<'static, Postgres>,
) -> Result<(), StripeStoreError> {
    query
        .build()
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(storage_error)
}

fn schema_error(error: crate::AuthError) -> StripeStoreError {
    StripeStoreError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn customer_queries_use_physical_columns_without_json_or_literal_values() {
        let store = super::super::test_support::store();
        let user = store.model("user").unwrap();
        let select = customer_query(&user, json!(Uuid::nil().to_string())).unwrap();
        assert!(select.sql().contains("FROM \"billing\"\"userss\""));
        assert!(select.sql().contains("SELECT \"stripe customer\""));
        assert!(!select.sql().contains("additional_fields"));
        let update = set_customer_query(
            &user,
            json!(Uuid::nil().to_string()),
            Some("cus_secret".into()),
        )
        .unwrap();
        assert!(update.sql().contains("SET \"stripe customer\" = $1"));
        assert!(!update.sql().contains("cus_secret"));
    }
}
