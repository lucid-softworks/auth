use super::{PostgresCreemStore, schema_error, storage_error};
use crate::{
    creem::{CreemStoreError, CreemStoredUser},
    postgres::PostgresModel,
};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder, Row};

pub(super) async fn find(
    store: &PostgresCreemStore,
    reference_id: &str,
) -> Result<Option<CreemStoredUser>, CreemStoreError> {
    let Some(model) = store
        .model_if_present("user")?
        .filter(|model| model.has_field("creemCustomerId"))
    else {
        return Ok(None);
    };
    let mut query = find_query(&model, reference_id)?;
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .map(|row| {
            let customer = row
                .try_get::<Option<String>, _>("creemCustomerId")
                .map_err(storage_error)?;
            let had_trial = row
                .try_get::<Option<bool>, _>("hadTrial")
                .map_err(storage_error)?;
            Ok(CreemStoredUser {
                reference_id: row
                    .try_get::<uuid::Uuid, _>("id")
                    .map_err(storage_error)?
                    .to_string(),
                creem_customer_id: customer.map(Value::String),
                had_trial: had_trial.map(Value::Bool),
            })
        })
        .transpose()
}

pub(super) async fn set_customer_id(
    store: &PostgresCreemStore,
    reference_id: &str,
    customer_id: &str,
) -> Result<(), CreemStoreError> {
    update(store, reference_id, "creemCustomerId", json!(customer_id)).await
}

pub(super) async fn set_had_trial(
    store: &PostgresCreemStore,
    reference_id: &str,
    had_trial: bool,
) -> Result<(), CreemStoreError> {
    update(store, reference_id, "hadTrial", json!(had_trial)).await
}

fn find_query(
    model: &PostgresModel<'_>,
    reference_id: &str,
) -> Result<QueryBuilder<'static, Postgres>, CreemStoreError> {
    let id = uuid::Uuid::parse_str(reference_id)
        .map_err(|error| CreemStoreError::Unavailable(error.to_string()))?;
    let mut query = QueryBuilder::new("SELECT \"id\" AS \"id\", ");
    query
        .push(
            model
                .quoted_column("creemCustomerId")
                .map_err(schema_error)?,
        )
        .push(" AS \"creemCustomerId\", ")
        .push(model.quoted_column("hadTrial").map_err(schema_error)?)
        .push(" AS \"hadTrial\" FROM ")
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ");
    model
        .encode("id", json!(id.to_string()))
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(" LIMIT 1");
    Ok(query)
}

fn update_query(
    model: &PostgresModel<'_>,
    reference_id: &str,
    field: &str,
    value: Value,
) -> Result<QueryBuilder<'static, Postgres>, CreemStoreError> {
    let id = uuid::Uuid::parse_str(reference_id)
        .map_err(|error| CreemStoreError::Unavailable(error.to_string()))?;
    let mut query = QueryBuilder::new("UPDATE ");
    query
        .push(model.quoted_table())
        .push(" SET ")
        .push(model.quoted_column(field).map_err(schema_error)?)
        .push(" = ");
    model
        .encode(field, value)
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(" WHERE \"id\" = ");
    model
        .encode("id", json!(id.to_string()))
        .map_err(schema_error)?
        .push_bind(&mut query);
    Ok(query)
}

async fn update(
    store: &PostgresCreemStore,
    reference_id: &str,
    field: &str,
    value: Value,
) -> Result<(), CreemStoreError> {
    let model = store.model("user")?;
    let mut query = update_query(&model, reference_id, field, value)?;
    query
        .build()
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(storage_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn user_queries_use_typed_physical_fields_without_json_storage() {
        let store = super::super::test_support::store();
        let model = store.model("user").unwrap();
        let find = find_query(&model, &uuid::Uuid::nil().to_string()).unwrap();
        assert!(find.sql().contains("FROM \"creem\"\"userss\""));
        assert!(
            find.sql()
                .contains("\"customer id\" AS \"creemCustomerId\"")
        );
        assert!(!find.sql().contains("additional_fields"));
        let update = update_query(
            &model,
            &uuid::Uuid::nil().to_string(),
            "hadTrial",
            json!(true),
        )
        .unwrap();
        assert!(update.sql().contains("SET \"used trial\" = $1"));
    }
}
