use super::super::{NewSsoProvider, SsoProvider, SsoProviderUpdate, SsoStoreError};
use crate::{AuthError, DashAdapterWhere, DatabaseTransaction, run_database_transaction};
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) async fn create(
    database: &super::DatabaseSsoStore,
    provider: NewSsoProvider,
) -> Result<SsoProvider, SsoStoreError> {
    let store = database.store.clone();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let record = super::codec::create_record(provider).map_err(auth_error)?;
            let created = transaction.create_record("ssoProvider", record).await?;
            super::codec::decode(&created).map_err(auth_error)
        })
    })
    .await
    .map_err(store_error)
}

pub(super) async fn list(
    database: &super::DatabaseSsoStore,
) -> Result<Vec<SsoProvider>, SsoStoreError> {
    let store = database.store.clone();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let records = transaction
                .find_records(
                    "ssoProvider",
                    &[],
                    None,
                    0,
                    None,
                    &[],
                )
                .await?;
            records
                .iter()
                .map(super::codec::decode)
                .collect::<Result<_, _>>()
                .map_err(auth_error)
        })
    })
    .await
    .map_err(store_error)
}

pub(super) async fn find(
    database: &super::DatabaseSsoStore,
    field: &str,
    value: &str,
) -> Result<Option<SsoProvider>, SsoStoreError> {
    let store = database.store.clone();
    let filter = equal(field, json!(value));
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move { find_one(&transaction, &[filter]).await })
    })
    .await
    .map_err(store_error)
}

pub(super) async fn update(
    database: &super::DatabaseSsoStore,
    id: &str,
    update: SsoProviderUpdate,
) -> Result<SsoProvider, SsoStoreError> {
    let store = database.store.clone();
    let id = id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let update = super::codec::update_record(update).map_err(auth_error)?;
            let record = transaction
                .update_record("ssoProvider", &[equal("id", json!(id))], update)
                .await?
                .ok_or_else(|| auth_error(SsoStoreError::NotFound))?;
            super::codec::decode(&record).map_err(auth_error)
        })
    })
    .await
    .map_err(store_error)
}

pub(super) async fn update_guarded(
    database: &super::DatabaseSsoStore,
    id: &str,
    provider_id: &str,
    update: SsoProviderUpdate,
    identity_boundary_changed: bool,
) -> Result<SsoProvider, SsoStoreError> {
    let store = database.store.clone();
    let id = id.to_owned();
    let provider_id = provider_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            if identity_boundary_changed
                && transaction
                    .count_records("account", &[equal("providerId", json!(provider_id))])
                    .await?
                    > 0
            {
                return Err(auth_error(SsoStoreError::LinkedAccounts));
            }
            let update = super::codec::update_record(update).map_err(auth_error)?;
            let record = transaction
                .update_record("ssoProvider", &[equal("id", json!(id))], update)
                .await?
                .ok_or_else(|| auth_error(SsoStoreError::NotFound))?;
            super::codec::decode(&record).map_err(auth_error)
        })
    })
    .await
    .map_err(store_error)
}

pub(super) async fn delete(
    database: &super::DatabaseSsoStore,
    id: &str,
) -> Result<Option<SsoProvider>, SsoStoreError> {
    let store = database.store.clone();
    let id = id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let filter = [equal("id", json!(id))];
            let found = find_one(&transaction, &filter).await?;
            if found.is_some() {
                transaction.delete_records("ssoProvider", &filter).await?;
            }
            Ok(found)
        })
    })
    .await
    .map_err(store_error)
}

pub(super) async fn delete_with_accounts(
    database: &super::DatabaseSsoStore,
    id: &str,
    provider_id: &str,
) -> Result<bool, SsoStoreError> {
    let store = database.store.clone();
    let id = id.to_owned();
    let provider_id = provider_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let provider_filter = [
                equal("id", json!(id)),
                equal("providerId", json!(provider_id)),
            ];
            if find_one(&transaction, &provider_filter).await?.is_none() {
                return Ok(false);
            }
            transaction
                .delete_records("account", &[equal("providerId", json!(provider_id))])
                .await?;
            transaction
                .delete_records("ssoProvider", &provider_filter)
                .await?;
            Ok(true)
        })
    })
    .await
    .map_err(store_error)
}

async fn find_one(
    transaction: &Arc<dyn DatabaseTransaction>,
    filter: &[DashAdapterWhere],
) -> Result<Option<SsoProvider>, AuthError> {
    let mut records = transaction
        .find_records("ssoProvider", filter, Some(1), 0, None, &[])
        .await?;
    records
        .pop()
        .as_ref()
        .map(super::codec::decode)
        .transpose()
        .map_err(auth_error)
}

fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: Default::default(),
        connector: None,
    }
}

fn auth_error(error: SsoStoreError) -> AuthError {
    AuthError::Storage(format!("lucid-sso-store:{error:?}"))
}

fn store_error(error: AuthError) -> SsoStoreError {
    let detail = error.to_string();
    let normalized = detail.to_ascii_lowercase();
    if normalized.contains("ssoprovider")
        && (normalized.contains("unique") || normalized.contains("duplicate"))
    {
        SsoStoreError::DuplicateProviderId
    } else if detail.contains("lucid-sso-store:NotFound") {
        SsoStoreError::NotFound
    } else if detail.contains("lucid-sso-store:LinkedAccounts") {
        SsoStoreError::LinkedAccounts
    } else {
        SsoStoreError::Storage(detail)
    }
}
