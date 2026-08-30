use super::AcquiredLease;
use crate::{AuthError, AuthStore, DatabaseTransaction, run_database_transaction};
use crate::scim::ScimError;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value, json};
use std::sync::Arc;

const LEASE_SECONDS: i64 = 300;

pub(super) async fn acquire(
    store: Arc<dyn AuthStore>,
    connection_id: &str,
    provisioning_domain_id: &str,
    now: DateTime<Utc>,
) -> Result<AcquiredLease, ScimError> {
    let connection_id = connection_id.to_owned();
    let domain = provisioning_domain_id.to_owned();
    run_database_transaction(store.as_ref(), move |database| {
        Box::pin(async move { acquire_in_transaction(&database, &connection_id, &domain, now).await })
    })
    .await
    .map_err(super::error)
}

async fn acquire_in_transaction(
    database: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    domain: &str,
    now: DateTime<Utc>,
) -> Result<AcquiredLease, AuthError> {
    let filter = [super::super::core::equal(
        "connectionKey",
        json!(super::super::keys::connection(connection_id)),
    )];
    let Some(binding) = super::super::core::find_one(database, "scimConnectionBinding", &filter)
        .await?
    else {
        return create_terminal_binding(database, connection_id, domain, now).await;
    };
    if string(&binding, "provisioningDomainId")? != domain {
        return Err(AuthError::Storage(format!(
            "SCIM connection \"{connection_id}\" is already bound to another provisioning domain"
        )));
    }
    let status = string(&binding, "decommissionStatus")?;
    let reconciled_users = number(&binding, "decommissionReconciledUserCount")? as usize;
    if status == "complete" || lease_is_active(&binding, now) {
        return Ok(AcquiredLease {
            binding_id: string(&binding, "id")?,
            lease_id: None,
            reconciled_users,
        });
    }
    let lease_id = crate::scim::random_urlsafe(32);
    let acquired = database
        .increment_record(
            "scimConnectionBinding",
            &[
                super::super::core::equal("id", field(&binding, "id")?.clone()),
                super::super::core::equal(
                    "decommissionRevision",
                    field(&binding, "decommissionRevision")?.clone(),
                ),
                super::super::core::equal("decommissionStatus", json!(status)),
            ],
            object(json!({"decommissionRevision": 1})),
            object(json!({
                "decommissionStatus": "reconciling",
                "decommissionedAt": binding.get("decommissionedAt").filter(|value| !value.is_null()).cloned().unwrap_or_else(|| super::super::codec::date(now)),
                "decommissionCompletedAt": null,
                "decommissionLeaseId": lease_id,
                "decommissionLeaseExpiresAt": super::super::codec::date(now + Duration::seconds(LEASE_SECONDS)),
            })),
        )
        .await?
        .ok_or_else(|| AuthError::Storage("SCIM connection changed while acquiring its decommission lease".into()))?;
    Ok(AcquiredLease {
        binding_id: string(&acquired, "id")?,
        lease_id: Some(lease_id),
        reconciled_users,
    })
}

async fn create_terminal_binding(
    database: &Arc<dyn DatabaseTransaction>,
    connection_id: &str,
    domain: &str,
    now: DateTime<Utc>,
) -> Result<AcquiredLease, AuthError> {
    let mut record = super::super::codec::binding_record(connection_id, domain, now);
    record.extend(object(json!({
        "decommissionedAt": super::super::codec::date(now),
        "decommissionStatus": "complete",
        "decommissionCompletedAt": super::super::codec::date(now),
    })));
    let created = database.create_record("scimConnectionBinding", record).await?;
    Ok(AcquiredLease {
        binding_id: string(&created, "id")?,
        lease_id: None,
        reconciled_users: 0,
    })
}

pub(super) async fn release(store: Arc<dyn AuthStore>, binding_id: &str, lease_id: &str) {
    let binding_id = binding_id.to_owned();
    let lease_id = lease_id.to_owned();
    let _ = run_database_transaction(store.as_ref(), move |database| {
        Box::pin(async move {
            let filter = [super::super::core::equal("id", json!(binding_id))];
            let Some(binding) = super::super::core::find_one(
                &database,
                "scimConnectionBinding",
                &filter,
            )
            .await?
            else {
                return Ok(());
            };
            if binding.get("decommissionLeaseId").and_then(Value::as_str)
                != Some(lease_id.as_str())
                || binding.get("decommissionStatus").and_then(Value::as_str) == Some("complete")
            {
                return Ok(());
            }
            database
                .increment_record(
                    "scimConnectionBinding",
                    &[
                        super::super::core::equal("id", json!(binding_id)),
                        super::super::core::equal("decommissionLeaseId", json!(lease_id)),
                        super::super::core::equal(
                            "decommissionRevision",
                            field(&binding, "decommissionRevision")?.clone(),
                        ),
                    ],
                    object(json!({"decommissionRevision": 1})),
                    object(json!({
                        "decommissionLeaseId": null,
                        "decommissionLeaseExpiresAt": null,
                    })),
                )
                .await?;
            Ok(())
        })
    })
    .await;
}

fn lease_is_active(binding: &Map<String, Value>, now: DateTime<Utc>) -> bool {
    binding.get("decommissionStatus").and_then(Value::as_str) == Some("reconciling")
        && binding.get("decommissionLeaseId").and_then(Value::as_str).is_some()
        && binding
            .get("decommissionLeaseExpiresAt")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .is_some_and(|expires| expires > now)
}

pub(super) fn field<'a>(record: &'a Map<String, Value>, name: &str) -> Result<&'a Value, AuthError> {
    record
        .get(name)
        .ok_or_else(|| AuthError::Storage(format!("SCIM binding field '{name}' is missing")))
}

pub(super) fn string(record: &Map<String, Value>, name: &str) -> Result<String, AuthError> {
    field(record, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| AuthError::Storage(format!("SCIM binding field '{name}' is invalid")))
}

pub(super) fn number(record: &Map<String, Value>, name: &str) -> Result<u64, AuthError> {
    field(record, name)?
        .as_u64()
        .ok_or_else(|| AuthError::Storage(format!("SCIM binding field '{name}' is invalid")))
}

pub(super) fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("record literal is an object")
}
