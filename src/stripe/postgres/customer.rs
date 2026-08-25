use super::{PostgresStripeStore, storage_error};
use crate::stripe::StripeStoreError;
use uuid::Uuid;

const USER_CUSTOMER_KEY: &str = "stripeCustomerId";

pub(super) async fn user_customer_id(
    store: &PostgresStripeStore,
    user_id: Uuid,
) -> Result<Option<String>, StripeStoreError> {
    sqlx::query_scalar(&user_customer_query(store))
        .bind(user_id)
        .fetch_optional(store.pool())
        .await
        .map(|value| value.flatten())
        .map_err(storage_error)
}

pub(super) async fn set_user_customer_id(
    store: &PostgresStripeStore,
    user_id: Uuid,
    customer_id: Option<String>,
) -> Result<(), StripeStoreError> {
    sqlx::query(&set_user_customer_query(store))
        .bind(user_id)
        .bind(customer_id)
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn user_id_by_customer(
    store: &PostgresStripeStore,
    customer_id: &str,
) -> Result<Option<Uuid>, StripeStoreError> {
    sqlx::query_scalar(&user_by_customer_query(store))
        .bind(customer_id)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)
}

pub(super) async fn organization_customer_id(
    store: &PostgresStripeStore,
    organization_id: Uuid,
) -> Result<Option<String>, StripeStoreError> {
    let Some(query) = organization_customer_query(store) else {
        return Ok(None);
    };
    sqlx::query_scalar(&query)
        .bind(organization_id)
        .fetch_optional(store.pool())
        .await
        .map(|value| value.flatten())
        .map_err(storage_error)
}

pub(super) async fn set_organization_customer_id(
    store: &PostgresStripeStore,
    organization_id: Uuid,
    customer_id: Option<String>,
) -> Result<(), StripeStoreError> {
    let Some(query) = set_organization_customer_query(store) else {
        return Ok(());
    };
    sqlx::query(&query)
        .bind(organization_id)
        .bind(customer_id)
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn organization_id_by_customer(
    store: &PostgresStripeStore,
    customer_id: &str,
) -> Result<Option<Uuid>, StripeStoreError> {
    let Some(query) = organization_by_customer_query(store) else {
        return Ok(None);
    };
    sqlx::query_scalar(&query)
        .bind(customer_id)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)
}

fn user_customer_query(store: &PostgresStripeStore) -> String {
    format!(
        "SELECT additional_fields ->> '{USER_CUSTOMER_KEY}' FROM {} WHERE id = $1",
        store.schema.user().table()
    )
}

fn set_user_customer_query(store: &PostgresStripeStore) -> String {
    format!(
        "UPDATE {} SET additional_fields = CASE \
         WHEN $2::TEXT IS NULL THEN COALESCE(additional_fields, '{{}}'::JSONB) - '{USER_CUSTOMER_KEY}' \
         ELSE jsonb_set(COALESCE(additional_fields, '{{}}'::JSONB), '{{{USER_CUSTOMER_KEY}}}', to_jsonb($2::TEXT), true) \
         END WHERE id = $1",
        store.schema.user().table()
    )
}

fn user_by_customer_query(store: &PostgresStripeStore) -> String {
    format!(
        "SELECT id FROM {} WHERE additional_fields ->> '{USER_CUSTOMER_KEY}' = $1 ORDER BY id LIMIT 1",
        store.schema.user().table()
    )
}

fn organization_customer_query(store: &PostgresStripeStore) -> Option<String> {
    let organization = store.schema.organization()?;
    Some(format!(
        "SELECT {} FROM {} WHERE id = $1",
        organization.column("stripeCustomerId"),
        organization.table()
    ))
}

fn set_organization_customer_query(store: &PostgresStripeStore) -> Option<String> {
    let organization = store.schema.organization()?;
    Some(format!(
        "UPDATE {} SET {} = $2 WHERE id = $1",
        organization.table(),
        organization.column("stripeCustomerId")
    ))
}

fn organization_by_customer_query(store: &PostgresStripeStore) -> Option<String> {
    let organization = store.schema.organization()?;
    Some(format!(
        "SELECT id FROM {} WHERE {} = $1 ORDER BY id LIMIT 1",
        organization.table(),
        organization.column("stripeCustomerId")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        postgres::PostgresStore,
        stripe::{StripeModelSchema, StripeSchema},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::collections::BTreeMap;

    fn store(schema: StripeSchema) -> PostgresStripeStore {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/lucid_auth")
            .unwrap();
        PostgresStripeStore::new(PostgresStore::new(pool), &schema, true, true).unwrap()
    }

    #[tokio::test]
    async fn user_customer_uses_the_logical_additional_field_key() {
        let store = store(StripeSchema {
            user: StripeModelSchema {
                model_name: Some("auth people".into()),
                fields: BTreeMap::from([("stripeCustomerId".into(), "billing id".into())]),
            },
            ..StripeSchema::default()
        });

        let select = user_customer_query(&store);
        let update = set_user_customer_query(&store);
        assert!(select.contains("\"auth people\""));
        assert!(select.contains("->> 'stripeCustomerId'"));
        assert!(!select.contains("billing id"));
        assert!(update.contains("'{stripeCustomerId}'"));
        assert!(update.contains("$2::TEXT"));
    }

    #[tokio::test]
    async fn organization_customer_uses_remapped_physical_identifiers() {
        let store = store(StripeSchema {
            organization: StripeModelSchema {
                model_name: Some("work spaces".into()),
                fields: BTreeMap::from([("stripeCustomerId".into(), "billing \"id\"".into())]),
            },
            ..StripeSchema::default()
        });

        let query = organization_by_customer_query(&store).unwrap();
        assert!(query.contains("\"work spaces\""));
        assert!(query.contains("\"billing \"\"id\"\"\""));
        assert!(query.ends_with("= $1 ORDER BY id LIMIT 1"));
    }
}
