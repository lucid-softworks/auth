use super::MemoryChargebeeStore;
use crate::{
    AdminListCondition, AdminListOperator, AdminListUsersQuery, UserProfileUpdate,
    chargebee::ChargebeeStoreError,
};
use serde_json::{Map, Value};
use uuid::Uuid;

const CUSTOMER_FIELD: &str = "chargebeeCustomerId";

pub(super) async fn user_customer_id(
    store: &MemoryChargebeeStore,
    user_id: Uuid,
) -> Result<Option<String>, ChargebeeStoreError> {
    store
        .auth_store
        .find_user_by_id(user_id)
        .await
        .map_err(auth_error)
        .map(|user| {
            user.and_then(|user| {
                user.additional_fields
                    .get(CUSTOMER_FIELD)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
        })
}

pub(super) async fn set_user_customer_id(
    store: &MemoryChargebeeStore,
    user_id: Uuid,
    customer_id: Option<String>,
) -> Result<(), ChargebeeStoreError> {
    let _guard = store.customer_write.lock().await;
    if let Some(customer_id) = &customer_id
        && user_id_by_customer(store, customer_id)
            .await?
            .is_some_and(|existing| existing != user_id)
    {
        return Err(ChargebeeStoreError::DuplicateCustomerId);
    }
    let additional_fields = Map::from_iter([(
        CUSTOMER_FIELD.to_owned(),
        customer_id.map_or(Value::Null, Value::String),
    )]);
    store
        .auth_store
        .update_user_profile(
            user_id,
            UserProfileUpdate {
                additional_fields,
                ..UserProfileUpdate::default()
            },
        )
        .await
        .map(|_| ())
        .map_err(auth_error)
}

pub(super) async fn user_id_by_customer(
    store: &MemoryChargebeeStore,
    customer_id: &str,
) -> Result<Option<Uuid>, ChargebeeStoreError> {
    let query = AdminListUsersQuery {
        limit: 1,
        conditions: vec![AdminListCondition {
            field: CUSTOMER_FIELD.into(),
            operator: AdminListOperator::Eq,
            value: Value::String(customer_id.to_owned()),
        }],
        ..AdminListUsersQuery::default()
    };
    store
        .auth_store
        .list_users(&query)
        .await
        .map_err(auth_error)
        .map(|users| users.into_iter().next().map(|user| user.id))
}

pub(super) async fn organization_customer_id(
    store: &MemoryChargebeeStore,
    organization_id: Uuid,
) -> Result<Option<String>, ChargebeeStoreError> {
    Ok(store
        .state
        .read()
        .await
        .organizations
        .get(&organization_id)
        .cloned())
}

pub(super) async fn set_organization_customer_id(
    store: &MemoryChargebeeStore,
    organization_id: Uuid,
    customer_id: Option<String>,
) -> Result<(), ChargebeeStoreError> {
    let mut state = store.state.write().await;
    if let Some(customer_id) = &customer_id
        && state
            .organizations
            .iter()
            .any(|(id, stored)| *id != organization_id && stored.as_str() == customer_id.as_str())
    {
        return Err(ChargebeeStoreError::DuplicateCustomerId);
    }
    match customer_id {
        Some(customer_id) => {
            state.organizations.insert(organization_id, customer_id);
        }
        None => {
            state.organizations.remove(&organization_id);
        }
    }
    Ok(())
}

pub(super) async fn organization_id_by_customer(
    store: &MemoryChargebeeStore,
    customer_id: &str,
) -> Result<Option<Uuid>, ChargebeeStoreError> {
    Ok(store
        .state
        .read()
        .await
        .organizations
        .iter()
        .find_map(|(id, stored)| (stored == customer_id).then_some(*id)))
}

fn auth_error(error: crate::AuthError) -> ChargebeeStoreError {
    ChargebeeStoreError::Unavailable(error.to_string())
}
