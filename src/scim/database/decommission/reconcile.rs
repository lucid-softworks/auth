use super::lease::{field, number, object, string};
use crate::{AuthError, AuthStore, DashAdapterOperator, DashAdapterSort, DashSortDirection};
use crate::{DatabaseTransaction, run_database_transaction};
use crate::scim::{ScimError, ScimOptions};
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc};

const BATCH_SIZE: usize = 50;
const LEASE_SECONDS: i64 = 300;

pub(super) async fn run(
    store: Arc<dyn AuthStore>,
    options: &ScimOptions,
    binding_id: &str,
    lease_id: &str,
) -> Result<usize, ScimError> {
    loop {
        let options = options.clone();
        let binding_id = binding_id.to_owned();
        let lease_id = lease_id.to_owned();
        let checkpoint = run_database_transaction(store.as_ref(), move |database| {
            Box::pin(async move { advance(database, options, &binding_id, &lease_id).await })
        })
        .await
        .map_err(super::error)?;
        if checkpoint.complete {
            return Ok(checkpoint.reconciled_users);
        }
    }
}

struct Checkpoint {
    complete: bool,
    reconciled_users: usize,
}

async fn advance(
    database: Arc<dyn DatabaseTransaction>,
    options: ScimOptions,
    binding_id: &str,
    lease_id: &str,
) -> Result<Checkpoint, AuthError> {
    let binding = super::super::core::find_one(
        &database,
        "scimConnectionBinding",
        &[super::super::core::equal("id", json!(binding_id))],
    )
    .await?
    .ok_or_else(|| AuthError::Storage("SCIM binding disappeared during decommissioning".into()))?;
    if string(&binding, "decommissionStatus")? == "complete" {
        return checkpoint(&binding, true);
    }
    if binding.get("decommissionLeaseId").and_then(Value::as_str) != Some(lease_id) {
        return Err(AuthError::Storage("SCIM decommission lease was taken over".into()));
    }
    let batch = find_batch(&database, &binding).await?;
    let renewed = renew(&database, &binding, lease_id).await?;
    let Some(batch) = batch else {
        return complete(&database, &renewed, lease_id, 0, None).await;
    };
    crate::scim::projection::reconcile_scim_users(
        &options,
        database.clone(),
        &string(&binding, "provisioningDomainId")?,
        &batch.scim_user_ids,
    )
    .await
    .map_err(super::transaction_error)?;
    for user_id in &batch.user_ids {
        let state = crate::scim::identity::state(&options, database.clone(), user_id)
            .await
            .map_err(super::transaction_error)?;
        if !state.active {
            database
                .delete_records(
                    "session",
                    &[super::super::core::equal("userId", json!(user_id))],
                )
                .await?;
        }
    }
    complete(
        &database,
        &renewed,
        lease_id,
        batch.user_ids.len(),
        Some((&batch.cursor_user_id, batch.has_more)),
    )
    .await
}

struct Batch {
    scim_user_ids: Vec<String>,
    user_ids: Vec<String>,
    cursor_user_id: String,
    has_more: bool,
}

async fn find_batch(
    database: &Arc<dyn DatabaseTransaction>,
    binding: &Map<String, Value>,
) -> Result<Option<Batch>, AuthError> {
    let mut filters = vec![super::super::core::equal(
        "provisioningDomainId",
        field(binding, "provisioningDomainId")?.clone(),
    )];
    if let Some(cursor) = binding.get("decommissionCursorUserId").filter(|value| !value.is_null()) {
        let mut filter = super::super::core::equal("userId", cursor.clone());
        filter.operator = DashAdapterOperator::Gt;
        filters.push(filter);
    }
    let records = database
        .find_records(
            "scimUser",
            &filters,
            Some(BATCH_SIZE + 1),
            0,
            Some(&DashAdapterSort {
                field: "userId".into(),
                direction: DashSortDirection::Asc,
            }),
            &[],
        )
        .await?;
    if records.is_empty() {
        return Ok(None);
    }
    let has_more = records.len() > BATCH_SIZE;
    let rows = records.into_iter().take(BATCH_SIZE).collect::<Vec<_>>();
    let cursor_user_id = string(rows.last().expect("batch is not empty"), "userId")?;
    let mut users = BTreeMap::new();
    for record in rows {
        users.entry(string(&record, "userId")?).or_insert(string(&record, "id")?);
    }
    Ok(Some(Batch {
        scim_user_ids: users.values().cloned().collect(),
        user_ids: users.keys().cloned().collect(),
        cursor_user_id,
        has_more,
    }))
}

async fn renew(
    database: &Arc<dyn DatabaseTransaction>,
    binding: &Map<String, Value>,
    lease_id: &str,
) -> Result<Map<String, Value>, AuthError> {
    database
        .increment_record(
            "scimConnectionBinding",
            &[
                super::super::core::equal("id", field(binding, "id")?.clone()),
                super::super::core::equal(
                    "decommissionRevision",
                    field(binding, "decommissionRevision")?.clone(),
                ),
                super::super::core::equal("decommissionStatus", json!("reconciling")),
                super::super::core::equal("decommissionLeaseId", json!(lease_id)),
            ],
            Map::new(),
            object(json!({
                "decommissionLeaseExpiresAt": super::super::codec::date(Utc::now() + Duration::seconds(LEASE_SECONDS)),
            })),
        )
        .await?
        .ok_or_else(|| AuthError::Storage("SCIM decommission lease changed before reconciliation".into()))
}

async fn complete(
    database: &Arc<dyn DatabaseTransaction>,
    binding: &Map<String, Value>,
    lease_id: &str,
    reconciled: usize,
    cursor: Option<(&str, bool)>,
) -> Result<Checkpoint, AuthError> {
    let now = Utc::now();
    let mut set = object(json!({
        "decommissionCursorUserId": cursor.map(|value| value.0),
    }));
    let done = cursor.is_none_or(|value| !value.1);
    if done {
        set.extend(object(json!({
            "decommissionStatus": "complete",
            "decommissionCompletedAt": super::super::codec::date(now),
            "decommissionLeaseId": null,
            "decommissionLeaseExpiresAt": null,
        })));
    } else {
        set.insert(
            "decommissionLeaseExpiresAt".into(),
            super::super::codec::date(now + Duration::seconds(LEASE_SECONDS)),
        );
    }
    let updated = database
        .increment_record(
            "scimConnectionBinding",
            &[
                super::super::core::equal("id", field(binding, "id")?.clone()),
                super::super::core::equal(
                    "decommissionRevision",
                    field(binding, "decommissionRevision")?.clone(),
                ),
                super::super::core::equal("decommissionLeaseId", json!(lease_id)),
            ],
            object(json!({
                "decommissionRevision": 1,
                "decommissionReconciledUserCount": reconciled,
                "decommissionBatchCount": usize::from(reconciled > 0),
            })),
            set,
        )
        .await?
        .ok_or_else(|| AuthError::Storage("SCIM decommission checkpoint changed concurrently".into()))?;
    checkpoint(&updated, done)
}

fn checkpoint(binding: &Map<String, Value>, complete: bool) -> Result<Checkpoint, AuthError> {
    Ok(Checkpoint {
        complete,
        reconciled_users: number(binding, "decommissionReconciledUserCount")? as usize,
    })
}
