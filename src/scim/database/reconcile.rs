use crate::scim::{ScimError, ScimOptions, ScimProjectionReconciliation};
use crate::{
    AuthError, AuthStore, DashAdapterOperator, DashAdapterSort, DashSortDirection,
    DatabaseTransaction, run_database_transaction,
};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc};

const BATCH_SIZE: usize = 50;

pub(in crate::scim) async fn run(
    store: Arc<dyn AuthStore>,
    options: Arc<ScimOptions>,
    provisioning_domain_id: &str,
) -> Result<ScimProjectionReconciliation, ScimError> {
    let mut cursor = None;
    let mut reconciled_users = 0;
    let mut batches = 0;
    loop {
        let options = options.clone();
        let domain = provisioning_domain_id.to_owned();
        let batch_cursor = cursor.clone();
        let batch = run_database_transaction(store.as_ref(), move |database| {
            Box::pin(async move { reconcile_batch(database, options, &domain, batch_cursor).await })
        })
        .await
        .map_err(super::decommission::error)?;
        let Some(batch) = batch else {
            break;
        };
        reconciled_users += batch.user_count;
        batches += 1;
        cursor = Some(batch.cursor_user_id);
        if !batch.has_more {
            break;
        }
    }
    Ok(ScimProjectionReconciliation {
        provisioning_domain_id: provisioning_domain_id.into(),
        reconciled_users,
        batches,
    })
}

struct BatchResult {
    cursor_user_id: String,
    user_count: usize,
    has_more: bool,
}

async fn reconcile_batch(
    database: Arc<dyn DatabaseTransaction>,
    options: Arc<ScimOptions>,
    domain: &str,
    cursor: Option<String>,
) -> Result<Option<BatchResult>, AuthError> {
    let records = find_records(&database, domain, cursor.as_deref()).await?;
    if records.is_empty() {
        return Ok(None);
    }
    let has_more = records.len() > BATCH_SIZE;
    let rows = records.into_iter().take(BATCH_SIZE).collect::<Vec<_>>();
    let cursor_user_id = string(rows.last().expect("batch is not empty"), "userId")?;
    let mut users = BTreeMap::new();
    for record in rows {
        users
            .entry(string(&record, "userId")?)
            .or_insert(string(&record, "id")?);
    }
    let scim_user_ids = users.values().cloned().collect::<Vec<_>>();
    crate::scim::projection::reconcile_scim_users(
        &options,
        database.clone(),
        domain,
        &scim_user_ids,
    )
    .await
    .map_err(super::decommission::transaction_error)?;
    for user_id in users.keys() {
        crate::scim::identity::state(&options, database.clone(), user_id)
            .await
            .map_err(super::decommission::transaction_error)?;
    }
    Ok(Some(BatchResult {
        cursor_user_id,
        user_count: users.len(),
        has_more,
    }))
}

async fn find_records(
    database: &Arc<dyn DatabaseTransaction>,
    domain: &str,
    cursor: Option<&str>,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let mut filters = vec![super::core::equal("provisioningDomainId", json!(domain))];
    if let Some(cursor) = cursor {
        let mut filter = super::core::equal("userId", json!(cursor));
        filter.operator = DashAdapterOperator::Gt;
        filters.push(filter);
    }
    database
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
        .await
}

fn string(record: &Map<String, Value>, field: &str) -> Result<String, AuthError> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AuthError::Storage(format!("SCIM projection field '{field}' is invalid")))
}
