use super::{PostgresChargebeeStore, storage_error};
use crate::chargebee::ChargebeeStoreError;
use uuid::Uuid;

const CUSTOMER_FIELD: &str = "chargebeeCustomerId";

pub(super) async fn user_customer_id(
    store: &PostgresChargebeeStore,
    user_id: Uuid,
) -> Result<Option<String>, ChargebeeStoreError> {
    sqlx::query_scalar(&format!(
        "SELECT additional_fields ->> '{CUSTOMER_FIELD}' FROM lucid_auth_users WHERE id = $1"
    ))
    .bind(user_id)
    .fetch_optional(store.pool())
    .await
    .map(|value: Option<Option<String>>| value.flatten())
    .map_err(storage_error)
}

pub(super) async fn set_user_customer_id(
    store: &PostgresChargebeeStore,
    user_id: Uuid,
    customer_id: Option<String>,
) -> Result<(), ChargebeeStoreError> {
    sqlx::query(&format!(
        "UPDATE lucid_auth_users SET additional_fields = CASE \
         WHEN $2::TEXT IS NULL THEN COALESCE(additional_fields, '{{}}'::JSONB) - '{CUSTOMER_FIELD}' \
         ELSE jsonb_set(COALESCE(additional_fields, '{{}}'::JSONB), '{{{CUSTOMER_FIELD}}}', \
         to_jsonb($2::TEXT), true) END WHERE id = $1"
    ))
    .bind(user_id)
    .bind(customer_id)
    .execute(store.pool())
    .await
    .map(|_| ())
    .map_err(storage_error)
}

pub(super) async fn user_id_by_customer(
    store: &PostgresChargebeeStore,
    customer_id: &str,
) -> Result<Option<Uuid>, ChargebeeStoreError> {
    sqlx::query_scalar(&format!(
        "SELECT id FROM lucid_auth_users WHERE additional_fields ->> '{CUSTOMER_FIELD}' = $1 \
         ORDER BY id LIMIT 1"
    ))
    .bind(customer_id)
    .fetch_optional(store.pool())
    .await
    .map_err(storage_error)
}

pub(super) async fn organization_customer_id(
    store: &PostgresChargebeeStore,
    organization_id: Uuid,
) -> Result<Option<String>, ChargebeeStoreError> {
    if !store.organization_enabled {
        return Ok(None);
    }
    sqlx::query_scalar("SELECT chargebee_customer_id FROM lucid_auth_organizations WHERE id = $1")
        .bind(organization_id)
        .fetch_optional(store.pool())
        .await
        .map(|value: Option<Option<String>>| value.flatten())
        .map_err(storage_error)
}

pub(super) async fn set_organization_customer_id(
    store: &PostgresChargebeeStore,
    organization_id: Uuid,
    customer_id: Option<String>,
) -> Result<(), ChargebeeStoreError> {
    if !store.organization_enabled {
        return Ok(());
    }
    sqlx::query("UPDATE lucid_auth_organizations SET chargebee_customer_id = $2 WHERE id = $1")
        .bind(organization_id)
        .bind(customer_id)
        .execute(store.pool())
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn organization_id_by_customer(
    store: &PostgresChargebeeStore,
    customer_id: &str,
) -> Result<Option<Uuid>, ChargebeeStoreError> {
    if !store.organization_enabled {
        return Ok(None);
    }
    sqlx::query_scalar(
        "SELECT id FROM lucid_auth_organizations WHERE chargebee_customer_id = $1 \
         ORDER BY id LIMIT 1",
    )
    .bind(customer_id)
    .fetch_optional(store.pool())
    .await
    .map_err(storage_error)
}
