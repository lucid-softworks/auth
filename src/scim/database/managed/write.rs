use super::codec;
use crate::{AuthError, DatabaseTransaction, run_database_transaction};
use crate::scim::{
    ScimManagedConnection, ScimManagedConnectionEvent, ScimManagedCredential, ScimStoreError,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

pub(in crate::scim::database) async fn create_connection(
    database: &super::super::DatabaseScimStore,
    creation_request_id: &str,
    connection: ScimManagedConnection,
    credential: ScimManagedCredential,
    events: Vec<ScimManagedConnectionEvent>,
) -> Result<(ScimManagedConnection, ScimManagedCredential), ScimStoreError> {
    let store = database.store.clone();
    let request_id = creation_request_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            if super::super::core::find_one(
                &transaction,
                "scimManagedConnection",
                &[super::super::core::equal("creationRequestId", json!(request_id))],
            )
            .await?
            .is_some()
            {
                return Err(super::super::core::auth_error(
                    ScimStoreError::CreationRequestConflict,
                ));
            }
            let connection_record = transaction
                .create_record(
                    "scimManagedConnection",
                    codec::connection_record(&connection),
                )
                .await?;
            let credential_record = transaction
                .create_record(
                    "scimManagedCredential",
                    codec::credential_record(&credential),
                )
                .await?;
            for event in events {
                transaction
                    .create_record("scimManagedConnectionEvent", codec::event_record(&event))
                    .await?;
            }
            Ok((
                codec::decode_connection(&connection_record)
                    .map_err(super::super::core::auth_error)?,
                codec::decode_credential(&credential_record)
                    .map_err(super::super::core::auth_error)?,
            ))
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

#[allow(clippy::too_many_arguments)]
pub(in crate::scim::database) async fn rotate_credential(
    database: &super::super::DatabaseScimStore,
    connection_id: &str,
    provisioning_domain_id: &str,
    credential: ScimManagedCredential,
    event: ScimManagedConnectionEvent,
    maximum: usize,
    now: DateTime<Utc>,
) -> Result<(ScimManagedConnection, ScimManagedCredential), ScimStoreError> {
    let store = database.store.clone();
    let connection_id = connection_id.to_owned();
    let domain = provisioning_domain_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let connection = require_connection(&transaction, &connection_id, &domain).await?;
            if connection.status != "active" {
                return Err(super::super::core::auth_error(ScimStoreError::Decommissioned));
            }
            let fenced = fence_connection(&transaction, &connection, "active", None).await?;
            let credentials = credential_records(&transaction, &connection.id).await?;
            let mut active = 0_usize;
            for record in credentials {
                if record.get("status").and_then(Value::as_str) != Some("active") {
                    continue;
                }
                let existing = codec::decode_credential(&record)
                    .map_err(super::super::core::auth_error)?;
                if existing.expires_at <= now {
                    transaction
                        .update_record(
                            "scimManagedCredential",
                            &[super::super::core::equal("id", json!(existing.id))],
                            codec::object(json!({
                                "status": "expired",
                                "activeSlotKey": format!("{}:inactive", existing.credential_id),
                            })),
                        )
                        .await?;
                } else {
                    active += 1;
                }
            }
            if active >= maximum {
                return Err(super::super::core::auth_error(ScimStoreError::CredentialLimit));
            }
            let credential_record = transaction
                .create_record(
                    "scimManagedCredential",
                    codec::credential_record(&credential),
                )
                .await?;
            let mut event = event;
            event.sequence = fenced.revision;
            transaction
                .create_record("scimManagedConnectionEvent", codec::event_record(&event))
                .await?;
            Ok((
                fenced,
                codec::decode_credential(&credential_record)
                    .map_err(super::super::core::auth_error)?,
            ))
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

pub(in crate::scim::database) async fn revoke_credential(
    database: &super::super::DatabaseScimStore,
    connection_record_id: &str,
    credential_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<ScimManagedCredential, ScimStoreError> {
    let store = database.store.clone();
    let record_id = connection_record_id.to_owned();
    let credential_id = credential_id.to_owned();
    let actor_id = actor_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let connection_record = super::super::core::find_one(
                &transaction,
                "scimManagedConnection",
                &[super::super::core::equal("id", json!(record_id))],
            )
            .await?
            .ok_or_else(|| super::super::core::auth_error(ScimStoreError::NotFound))?;
            let connection = codec::decode_connection(&connection_record)
                .map_err(super::super::core::auth_error)?;
            let filter = [
                super::super::core::equal("connectionRecordId", json!(record_id)),
                super::super::core::equal("credentialId", json!(credential_id)),
            ];
            let credential_record = super::super::core::find_one(
                &transaction,
                "scimManagedCredential",
                &filter,
            )
            .await?
            .ok_or_else(|| {
                super::super::core::auth_error(ScimStoreError::CredentialNotFound)
            })?;
            let credential = codec::decode_credential(&credential_record)
                .map_err(super::super::core::auth_error)?;
            if credential.status == "revoked" {
                return Ok(credential);
            }
            if connection.status != "active" || credential.status != "active" {
                return Err(super::super::core::auth_error(ScimStoreError::CredentialLimit));
            }
            let fenced = fence_connection(&transaction, &connection, "active", None).await?;
            let updated = transaction
                .update_record(
                    "scimManagedCredential",
                    &filter,
                    codec::object(json!({
                        "status": "revoked",
                        "activeSlotKey": format!("{}:inactive", credential.credential_id),
                        "revokedAt": codec::date(now),
                        "revokedBy": actor_id,
                    })),
                )
                .await?
                .ok_or_else(|| {
                    super::super::core::auth_error(ScimStoreError::ConcurrentMutation)
                })?;
            let event = codec::event(
                &connection.id,
                fenced.revision,
                "credential.revoked",
                &actor_id,
                Some(&credential_id),
                now,
            );
            transaction
                .create_record("scimManagedConnectionEvent", codec::event_record(&event))
                .await?;
            codec::decode_credential(&updated).map_err(super::super::core::auth_error)
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

pub(in crate::scim::database) async fn touch_credential(
    database: &super::super::DatabaseScimStore,
    credential_id: &str,
    now: DateTime<Utc>,
    minimum_interval_seconds: u64,
) -> Result<(), ScimStoreError> {
    let store = database.store.clone();
    let credential_id = credential_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let filter = [super::super::core::equal("credentialId", json!(credential_id))];
            let record = super::super::core::find_one(
                &transaction,
                "scimManagedCredential",
                &filter,
            )
            .await?
            .ok_or_else(|| {
                super::super::core::auth_error(ScimStoreError::CredentialNotFound)
            })?;
            let credential = codec::decode_credential(&record)
                .map_err(super::super::core::auth_error)?;
            if credential.last_used_at.is_none_or(|last| {
                now - last >= Duration::seconds(minimum_interval_seconds as i64)
            }) {
                transaction
                    .update_record(
                        "scimManagedCredential",
                        &filter,
                        codec::object(json!({"lastUsedAt": codec::date(now)})),
                    )
                    .await?;
            }
            Ok(())
        })
    })
    .await
    .map_err(super::super::core::store_error)
}

pub(super) async fn require_connection(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    domain: &str,
) -> Result<ScimManagedConnection, AuthError> {
    let record = super::super::core::find_one(
        transaction,
        "scimManagedConnection",
        &[
            super::super::core::equal("connectionId", json!(connection_id)),
            super::super::core::equal("provisioningDomainId", json!(domain)),
        ],
    )
    .await?
    .ok_or_else(|| super::super::core::auth_error(ScimStoreError::NotFound))?;
    codec::decode_connection(&record).map_err(super::super::core::auth_error)
}

pub(super) async fn fence_connection(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection: &ScimManagedConnection,
    status: &str,
    set: Option<serde_json::Map<String, Value>>,
) -> Result<ScimManagedConnection, AuthError> {
    let record = transaction
        .increment_record(
            "scimManagedConnection",
            &[
                super::super::core::equal("id", json!(connection.id)),
                super::super::core::equal("status", json!(status)),
                super::super::core::equal("revision", json!(connection.revision)),
            ],
            codec::object(json!({"revision": 1})),
            set.unwrap_or_default(),
        )
        .await?
        .ok_or_else(|| super::super::core::auth_error(ScimStoreError::ConcurrentMutation))?;
    codec::decode_connection(&record).map_err(super::super::core::auth_error)
}

pub(super) async fn credential_records(
    transaction: &Arc<dyn DatabaseTransaction>,
    connection_record_id: &str,
) -> Result<Vec<serde_json::Map<String, Value>>, AuthError> {
    transaction
        .find_records(
            "scimManagedCredential",
            &[super::super::core::equal(
                "connectionRecordId",
                json!(connection_record_id),
            )],
            None,
            0,
            None,
            &[],
        )
        .await
}
