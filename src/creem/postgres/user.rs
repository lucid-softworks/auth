use super::{PostgresCreemStore, storage_error};
use crate::creem::{CreemStoreError, CreemStoredUser};
use serde_json::Value;
use sqlx::FromRow;

const CUSTOMER_KEY: &str = "creemCustomerId";
const HAD_TRIAL_KEY: &str = "hadTrial";

#[derive(FromRow)]
struct UserBillingRow {
    reference_id: String,
    creem_customer_id: Option<Value>,
    had_trial: Option<Value>,
}

pub(super) async fn find(
    store: &PostgresCreemStore,
    reference_id: &str,
) -> Result<Option<CreemStoredUser>, CreemStoreError> {
    let Some(query) = find_query(store) else {
        return Ok(None);
    };
    sqlx::query_as::<_, UserBillingRow>(&query)
        .bind(reference_id)
        .fetch_optional(store.pool())
        .await
        .map(|row| {
            row.map(|row| CreemStoredUser {
                reference_id: row.reference_id,
                creem_customer_id: row.creem_customer_id,
                had_trial: row.had_trial,
            })
        })
        .map_err(storage_error)
}

pub(super) async fn set_customer_id(
    store: &PostgresCreemStore,
    reference_id: &str,
    customer_id: &str,
) -> Result<(), CreemStoreError> {
    let Some(query) = set_json_field_query(store, CUSTOMER_KEY, "TEXT") else {
        return Ok(());
    };
    sqlx::query(&query)
        .bind(reference_id)
        .bind(customer_id)
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn set_had_trial(
    store: &PostgresCreemStore,
    reference_id: &str,
    had_trial: bool,
) -> Result<(), CreemStoreError> {
    let Some(query) = set_json_field_query(store, HAD_TRIAL_KEY, "BOOLEAN") else {
        return Ok(());
    };
    sqlx::query(&query)
        .bind(reference_id)
        .bind(had_trial)
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(storage_error)
}

fn find_query(store: &PostgresCreemStore) -> Option<String> {
    let user = store.schema.user()?;
    Some(format!(
        "SELECT id::TEXT AS reference_id, additional_fields -> '{CUSTOMER_KEY}' AS creem_customer_id, \
         additional_fields -> '{HAD_TRIAL_KEY}' AS had_trial FROM {} WHERE id::TEXT = $1 LIMIT 1",
        user.table()
    ))
}

fn set_json_field_query(
    store: &PostgresCreemStore,
    field: &str,
    postgres_type: &str,
) -> Option<String> {
    let user = store.schema.user()?;
    Some(format!(
        "UPDATE {} SET additional_fields = jsonb_set(\
         COALESCE(additional_fields, '{{}}'::JSONB), '{{{field}}}', \
         to_jsonb($2::{postgres_type}), true) \
         WHERE id::TEXT = $1",
        user.table()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreemModelSchema, CreemSchema, postgres::PostgresStore};
    use sqlx::postgres::PgPoolOptions;
    use std::collections::BTreeMap;

    fn store(schema: CreemSchema) -> PostgresCreemStore {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/lucid_auth")
            .unwrap();
        PostgresCreemStore::new(PostgresStore::new(pool), &schema, true).unwrap()
    }

    #[tokio::test]
    async fn user_queries_use_the_remapped_table_and_logical_json_keys() {
        let mut schema = CreemSchema::default();
        schema.insert_model(
            "user",
            CreemModelSchema {
                model_name: Some("auth people".into()),
                fields: BTreeMap::from([
                    ("creemCustomerId".into(), "billing customer".into()),
                    ("hadTrial".into(), "trial history".into()),
                ]),
            },
        );
        let store = store(schema);
        let select = find_query(&store).unwrap();
        let customer = set_json_field_query(&store, CUSTOMER_KEY, "TEXT").unwrap();
        let trial = set_json_field_query(&store, HAD_TRIAL_KEY, "BOOLEAN").unwrap();

        assert!(select.contains("FROM \"auth people\""));
        assert!(select.contains("-> 'creemCustomerId'"));
        assert!(select.contains("-> 'hadTrial'"));
        assert!(!select.contains("billing customer"));
        assert!(!select.contains("trial history"));
        assert!(customer.contains("'{creemCustomerId}'"));
        assert!(customer.contains("$2::TEXT"));
        assert!(trial.contains("'{hadTrial}'"));
        assert!(trial.contains("$2::BOOLEAN"));
        assert!(select.contains("id::TEXT = $1"));
    }
}
