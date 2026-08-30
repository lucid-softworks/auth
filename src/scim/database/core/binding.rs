use super::{auth_error, equal, find_one, store_error};
use crate::{AuthError, run_database_transaction};
use crate::scim::{ScimConnectionBinding, ScimStoreError};
use chrono::{DateTime, Utc};
use serde_json::json;

pub(in crate::scim::database) async fn bind_connection(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    provisioning_domain_id: &str,
    now: DateTime<Utc>,
) -> Result<ScimConnectionBinding, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let provisioning_domain_id = provisioning_domain_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let filter = [equal(
                "connectionKey",
                json!(super::super::keys::connection(&connection_id)),
            )];
            if let Some(record) = find_one(&transaction, "scimConnectionBinding", &filter).await? {
                let binding = super::super::codec::decode_binding(&record).map_err(auth_error)?;
                validate(&binding, &provisioning_domain_id)?;
                return Ok(binding);
            }
            let record = super::super::codec::binding_record(
                &connection_id,
                &provisioning_domain_id,
                now,
            );
            let record = transaction
                .create_record("scimConnectionBinding", record)
                .await?;
            super::super::codec::decode_binding(&record).map_err(auth_error)
        })
    })
    .await
    .map_err(store_error)
}

pub(in crate::scim::database) async fn decommission_connection(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    provisioning_domain_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let provisioning_domain_id = provisioning_domain_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let binding_filter = [equal(
                "connectionKey",
                json!(super::super::keys::connection(&connection_id)),
            )];
            let record = find_one(&transaction, "scimConnectionBinding", &binding_filter)
                .await?
                .ok_or_else(|| auth_error(ScimStoreError::NotFound))?;
            let binding = super::super::codec::decode_binding(&record).map_err(auth_error)?;
            if binding.provisioning_domain_id != provisioning_domain_id {
                return Err(auth_error(ScimStoreError::NotFound));
            }
            let users = transaction
                .find_records(
                    "scimUser",
                    &[equal("connectionId", json!(connection_id))],
                    None,
                    0,
                    None,
                    &["id".into()],
                )
                .await?;
            transaction
                .update_record(
                    "scimConnectionBinding",
                    &binding_filter,
                    super::super::codec::object(json!({
                        "decommissionedAt": super::super::codec::date(now),
                        "decommissionStatus": "complete",
                        "decommissionCompletedAt": super::super::codec::date(now),
                    })),
                )
                .await?;
            for model in ["scimProjectionGrant", "scimGroupMember", "scimGroup", "scimUser"] {
                transaction
                    .delete_records(model, &[equal("connectionId", json!(connection_id))])
                    .await?;
            }
            Ok(users.len())
        })
    })
    .await
    .map_err(store_error)
}

fn validate(binding: &ScimConnectionBinding, provisioning_domain_id: &str) -> Result<(), AuthError> {
    if binding.provisioning_domain_id != provisioning_domain_id {
        return Err(auth_error(ScimStoreError::BindingConflict));
    }
    if binding.decommissioned_at.is_some() {
        return Err(auth_error(ScimStoreError::Decommissioned));
    }
    Ok(())
}
