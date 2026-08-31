use super::model::DirectoryRow;
use crate::{
    AuthError, AuthStore, DashAdapterOperator, DashAdapterSort, DashAdapterWhere,
    DatabaseTransaction, run_database_transaction,
};
use chrono::Utc;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

const MODEL: &str = "directorySyncConnection";

pub(super) struct NewDirectory<'a> {
    pub organization_id: &'a str,
    pub provider_id: &'a str,
    pub actor_id: &'a str,
    pub creation_request_id: Option<&'a str>,
}

pub(super) async fn list(
    store: Arc<dyn AuthStore>,
    organization_id: &str,
) -> Result<Vec<DirectoryRow>, AuthError> {
    let organization_id = organization_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let sort = DashAdapterSort {
                field: "createdAt".into(),
                direction: crate::DashSortDirection::Desc,
            };
            transaction
                .find_records(
                    MODEL,
                    &[equal("organizationId", organization_id)],
                    None,
                    0,
                    Some(&sort),
                    &[],
                )
                .await?
                .into_iter()
                .map(parse)
                .collect()
        })
    })
    .await
}

pub(super) async fn get(
    store: Arc<dyn AuthStore>,
    organization_id: &str,
    provider_id: &str,
) -> Result<Option<DirectoryRow>, AuthError> {
    let organization_id = organization_id.to_owned();
    let provider_id = provider_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            find(
                transaction.as_ref(),
                &[equal("organizationId", organization_id), equal("providerId", provider_id)],
            )
            .await
        })
    })
    .await
}

pub(super) async fn reserve(
    store: Arc<dyn AuthStore>,
    input: NewDirectory<'_>,
) -> Result<DirectoryRow, AuthError> {
    let organization_id = input.organization_id.to_owned();
    let provider_id = input.provider_id.to_owned();
    let actor_id = input.actor_id.to_owned();
    let creation_request_id = input
        .creation_request_id
        .map(str::to_owned)
        .unwrap_or_else(|| crate::scim::random_urlsafe(32));
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            if find(
                transaction.as_ref(),
                &[equal("organizationId", organization_id.clone()), equal("status", "active")],
            )
            .await?
            .is_some()
            {
                return Err(AuthError::Storage(
                    "This organization already has an active directory sync connection".into(),
                ));
            }
            let alias_key = alias_key(&organization_id, &provider_id);
            let now = Utc::now();
            let row = DirectoryRow {
                id: crate::scim::random_urlsafe(32),
                organization_id: organization_id.clone(),
                provider_id: provider_id.clone(),
                alias_key: alias_key.clone(),
                provisioning_domain_id: provisioning_domain_id(&organization_id, &provider_id),
                active_organization_key: format!("directory-sync-active:{}", digest(&organization_id)),
                connection_id: None,
                creation_request_id,
                status: "active".into(),
                revision: 0,
                created_at: now,
                created_by_actor_id: actor_id.clone(),
                updated_at: now,
                last_actor_id: actor_id,
                sso_provider_id: None,
                sso_provider_record_id: None,
                active_sso_provider_key: format!("directory-sync-sso-inactive:{alias_key}"),
                serialized_sso_pairing: None,
                pairing_enforced: false,
                unpaired_at: None,
                unpaired_by: None,
                decommission_started_at: None,
                decommissioned_at: None,
                last_error: None,
            };
            parse(transaction.create_record(MODEL, row.into_map().map_err(json_error)?).await?)
        })
    })
    .await
}

pub(super) async fn bind(
    store: Arc<dyn AuthStore>,
    row: &DirectoryRow,
    connection_id: &str,
) -> Result<DirectoryRow, AuthError> {
    let id = row.id.clone();
    let connection_id = connection_id.to_owned();
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let updated = transaction
                .update_record(
                    MODEL,
                    &[equal("id", id), equal("revision", 0_u64), equal_value("connectionId", Value::Null)],
                    map(json!({
                        "connectionId": connection_id,
                        "revision": 1,
                        "updatedAt": Utc::now(),
                    }))?,
                )
                .await?
                .ok_or_else(|| AuthError::Storage("Directory sync catalog binding changed".into()))?;
            parse(updated)
        })
    })
    .await
}

pub(super) async fn touch_active(
    store: Arc<dyn AuthStore>,
    row: &DirectoryRow,
    actor_id: &str,
) -> Result<DirectoryRow, AuthError> {
    update_fenced(
        store,
        row,
        vec![equal("status", "active")],
        json!({
            "revision": row.revision + 1,
            "updatedAt": Utc::now(),
            "lastActorId": actor_id,
            "lastError": null,
        }),
    )
    .await
}

pub(super) async fn start_decommission(
    store: Arc<dyn AuthStore>,
    row: &DirectoryRow,
    actor_id: &str,
) -> Result<DirectoryRow, AuthError> {
    update_fenced(
        store,
        row,
        vec![equal("status", "active")],
        json!({
            "status": "decommissioning",
            "revision": row.revision + 1,
            "decommissionStartedAt": Utc::now(),
            "updatedAt": Utc::now(),
            "lastActorId": actor_id,
        }),
    )
    .await
}

pub(super) async fn finish_decommission(
    store: Arc<dyn AuthStore>,
    row: &DirectoryRow,
    actor_id: &str,
) -> Result<DirectoryRow, AuthError> {
    update_fenced(
        store,
        row,
        vec![equal("status", "decommissioning")],
        json!({
            "activeOrganizationKey": format!("directory-sync-inactive:{}", row.alias_key),
            "activeSsoProviderKey": format!("directory-sync-sso-terminal:{}", row.alias_key),
            "status": "decommissioned",
            "revision": row.revision + 1,
            "decommissionedAt": Utc::now(),
            "updatedAt": Utc::now(),
            "lastActorId": actor_id,
        }),
    )
    .await
}

pub(super) async fn unpair(
    store: Arc<dyn AuthStore>,
    row: &DirectoryRow,
    actor_id: &str,
) -> Result<DirectoryRow, AuthError> {
    update_fenced(
        store,
        row,
        vec![equal("status", "decommissioned"), equal("pairingEnforced", true)],
        json!({
            "pairingEnforced": false,
            "revision": row.revision + 1,
            "unpairedAt": Utc::now(),
            "unpairedBy": actor_id,
            "updatedAt": Utc::now(),
            "lastActorId": actor_id,
        }),
    )
    .await
}

async fn update_fenced(
    store: Arc<dyn AuthStore>,
    row: &DirectoryRow,
    mut conditions: Vec<DashAdapterWhere>,
    update: Value,
) -> Result<DirectoryRow, AuthError> {
    conditions.push(equal("id", row.id.clone()));
    conditions.push(equal("revision", row.revision));
    run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let updated = transaction
                .update_record(MODEL, &conditions, map(update)?)
                .await?
                .ok_or_else(|| AuthError::Storage("Directory sync connection changed".into()))?;
            parse(updated)
        })
    })
    .await
}

async fn find(
    transaction: &dyn DatabaseTransaction,
    where_clause: &[DashAdapterWhere],
) -> Result<Option<DirectoryRow>, AuthError> {
    transaction
        .find_records(MODEL, where_clause, Some(1), 0, None, &[])
        .await?
        .into_iter()
        .next()
        .map(parse)
        .transpose()
}

fn equal(field: &str, value: impl Into<Value>) -> DashAdapterWhere {
    equal_value(field, value.into())
}

fn equal_value(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: DashAdapterOperator::Eq,
        connector: None,
    }
}

fn alias_key(organization_id: &str, provider_id: &str) -> String {
    let input = serde_json::to_string(&(organization_id, provider_id))
        .expect("directory alias input serializes");
    format!("directory-sync-alias:{}", digest(&input))
}

fn provisioning_domain_id(organization_id: &str, provider_id: &str) -> String {
    let input = format!(
        "{{\"purpose\":\"directory-sync-management\",\"organizationId\":{},\"providerId\":{}}}",
        serde_json::to_string(organization_id).expect("organization id serializes"),
        serde_json::to_string(provider_id).expect("provider id serializes"),
    );
    format!("dash_scim_domain_{}", digest(&input))
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn parse(row: Map<String, Value>) -> Result<DirectoryRow, AuthError> {
    DirectoryRow::from_map(row).map_err(json_error)
}

fn map(value: Value) -> Result<Map<String, Value>, AuthError> {
    let Value::Object(map) = value else {
        unreachable!("directory updates serialize as objects")
    };
    Ok(map)
}

fn json_error(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!("invalid directory sync catalog row: {error}"))
}
