use super::codec;
use crate::{DashAdapterSort, DashSortDirection, run_database_transaction};
use crate::scim::{
    ScimManagedConnection, ScimManagedConnectionEvent, ScimManagedCredential, ScimStoreError,
};
use serde_json::json;

pub(in crate::scim::database) async fn list_connections(
    database: &super::super::DatabaseScimStore,
    provisioning_domain_id: &str,
) -> Result<Vec<ScimManagedConnection>, ScimStoreError> {
    let store = database.store.clone();
    let domain = provisioning_domain_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let records = transaction
                .find_records(
                    "scimManagedConnection",
                    &[super::super::core::equal("provisioningDomainId", json!(domain))],
                    None,
                    0,
                    Some(&DashAdapterSort {
                        field: "createdAt".into(),
                        direction: DashSortDirection::Desc,
                    }),
                    &[],
                )
                .await?;
            records
                .iter()
                .map(codec::decode_connection)
                .collect::<Result<Vec<_>, _>>()
                .map_err(super::super::core::auth_error)
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

pub(in crate::scim::database) async fn find_connection(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    provisioning_domain_id: &str,
) -> Result<Option<ScimManagedConnection>, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let domain = provisioning_domain_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let record = super::super::core::find_one(
                &transaction,
                "scimManagedConnection",
                &[
                    super::super::core::equal("connectionId", json!(connection_id)),
                    super::super::core::equal("provisioningDomainId", json!(domain)),
                ],
            )
            .await?;
            record
                .as_ref()
                .map(codec::decode_connection)
                .transpose()
                .map_err(super::super::core::auth_error)
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

pub(in crate::scim::database) async fn list_credentials(
    database: &super::super::DatabaseScimStore,
    connection_record_id: &str,
) -> Result<Vec<ScimManagedCredential>, ScimStoreError> {
    let store = database.store.clone();
    let record_id = connection_record_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let records = transaction
                .find_records(
                    "scimManagedCredential",
                    &[super::super::core::equal("connectionRecordId", json!(record_id))],
                    None,
                    0,
                    Some(&DashAdapterSort {
                        field: "createdAt".into(),
                        direction: DashSortDirection::Desc,
                    }),
                    &[],
                )
                .await?;
            records
                .iter()
                .map(codec::decode_credential)
                .collect::<Result<Vec<_>, _>>()
                .map_err(super::super::core::auth_error)
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

pub(in crate::scim::database) async fn find_credential(
    database: &super::super::DatabaseScimStore,
    credential_id: &str,
) -> Result<Option<(ScimManagedConnection, ScimManagedCredential)>, ScimStoreError> {
    let store = database.store.clone();
    let credential_id = credential_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let credential = super::super::core::find_one(
                &transaction,
                "scimManagedCredential",
                &[super::super::core::equal("credentialId", json!(credential_id))],
            )
            .await?;
            let Some(credential) = credential else {
                return Ok(None);
            };
            let record_id = credential.get("connectionRecordId").cloned().unwrap_or_default();
            let connection = super::super::core::find_one(
                &transaction,
                "scimManagedConnection",
                &[super::super::core::equal("id", record_id)],
            )
            .await?;
            let Some(connection) = connection else {
                return Ok(None);
            };
            Ok(Some((
                codec::decode_connection(&connection)
                    .map_err(super::super::core::auth_error)?,
                codec::decode_credential(&credential)
                    .map_err(super::super::core::auth_error)?,
            )))
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

pub(in crate::scim::database) async fn list_events(
    database: &super::super::DatabaseScimStore,
    connection_record_id: &str,
) -> Result<Vec<ScimManagedConnectionEvent>, ScimStoreError> {
    let store = database.store.clone();
    let record_id = connection_record_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let records = transaction
                .find_records(
                    "scimManagedConnectionEvent",
                    &[super::super::core::equal("connectionRecordId", json!(record_id))],
                    Some(100),
                    0,
                    Some(&DashAdapterSort {
                        field: "sequence".into(),
                        direction: DashSortDirection::Desc,
                    }),
                    &[],
                )
                .await?;
            let mut events = records
                .iter()
                .map(codec::decode_event)
                .collect::<Result<Vec<_>, _>>()
                .map_err(super::super::core::auth_error)?;
            events.reverse();
            Ok(events)
        })
    })
    .await
    .map_err(super::super::core::store_error)
}
