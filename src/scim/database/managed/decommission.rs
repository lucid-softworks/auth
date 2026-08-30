use super::{codec, write};
use crate::scim::{ScimManagedConnection, ScimStoreError};
use crate::{AuthError, DatabaseTransaction, run_database_transaction};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

pub(in crate::scim::database) async fn decommission(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    provisioning_domain_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<ScimManagedConnection, ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let domain = provisioning_domain_id.to_owned();
    let actor_id = actor_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let connection = write::require_connection(&transaction, &connection_id, &domain).await?;
            if connection.status == "decommissioned" {
                return Ok(connection);
            }
            let mut current = connection;
            if current.status == "active" {
                current = write::fence_connection(
                    &transaction,
                    &current,
                    "active",
                    Some(codec::object(json!({
                        "status": "decommissioning",
                        "decommissionStartedAt": codec::date(now),
                        "decommissionStartedBy": actor_id,
                    }))),
                )
                .await?;
                decommission_credentials(&transaction, &current.id, now).await?;
                create_event(&transaction, &current, "connection.decommissioning", &actor_id, now)
                    .await?;
            }
            let completed = write::fence_connection(
                &transaction,
                &current,
                "decommissioning",
                Some(codec::object(json!({
                    "status": "decommissioned",
                    "decommissionedAt": codec::date(now),
                    "decommissionedBy": actor_id,
                }))),
            )
            .await?;
            create_event(&transaction, &completed, "connection.decommissioned", &actor_id, now)
                .await?;
            Ok(completed)
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

async fn decommission_credentials(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_record_id: &str,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    for record in write::credential_records(transaction, connection_record_id).await? {
        if record.get("status").and_then(Value::as_str) == Some("active") {
            let credential = codec::decode_credential(&record)
                .map_err(super::super::core::auth_error)?;
            transaction
                .update_record(
                    "scimManagedCredential",
                    &[super::super::core::equal("id", json!(credential.id))],
                    codec::object(json!({
                        "status": "decommissioned",
                        "activeSlotKey": format!("{}:inactive", credential.credential_id),
                        "decommissionedAt": codec::date(now),
                    })),
                )
                .await?;
        }
    }
    Ok(())
}

async fn create_event(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection: &ScimManagedConnection,
    kind: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let event = codec::event(&connection.id, connection.revision, kind, actor_id, None, now);
    transaction
        .create_record("scimManagedConnectionEvent", codec::event_record(&event))
        .await?;
    Ok(())
}
