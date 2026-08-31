use super::codec;
pub(super) use super::codec::{
    decode_agent, decode_approval, decode_grant, decode_host, millis, normalize_agent,
    normalize_approval, normalize_grant, normalize_host, normalize_plan,
};
use crate::{
    AuthError,
    agent_auth::AgentAuthSnapshot,
    mysql::{MySqlFilter, MySqlFindOptions, MySqlStore, query::execute},
};
use serde_json::{Map, Value, json};
use sqlx::{MySql, MySqlConnection, Transaction};
use std::collections::HashMap;

pub(super) async fn begin_immediate(
    store: &MySqlStore,
) -> Result<Transaction<'static, MySql>, AuthError> {
    store.pool.begin().await.map_err(storage)
}

pub(super) async fn commit(connection: Transaction<'static, MySql>) -> Result<(), AuthError> {
    connection.commit().await.map_err(storage)
}

pub(super) async fn rollback(connection: Transaction<'static, MySql>) {
    let _ = connection.rollback().await;
}

pub(super) async fn load_snapshot(
    store: &MySqlStore,
    connection: &mut MySqlConnection,
) -> Result<AgentAuthSnapshot, AuthError> {
    let schema = store.physical_schema()?;
    Ok(AgentAuthSnapshot {
        hosts: load(connection, schema, "agentHost", codec::decode_host).await?,
        agents: load(connection, schema, "agent", codec::decode_agent).await?,
        grants: load(
            connection,
            schema,
            "agentCapabilityGrant",
            codec::decode_grant,
        )
        .await?,
        approvals: load(
            connection,
            schema,
            "approvalRequest",
            codec::decode_approval,
        )
        .await?,
    })
}

pub(super) async fn sync_snapshot(
    store: &MySqlStore,
    connection: &mut MySqlConnection,
    before: &AgentAuthSnapshot,
    after: &AgentAuthSnapshot,
) -> Result<(), AuthError> {
    let schema = store.physical_schema()?;
    sync_model(
        connection,
        schema,
        "agentHost",
        &before.hosts,
        &after.hosts,
        codec::host_record,
    )
    .await?;
    sync_model(
        connection,
        schema,
        "agent",
        &before.agents,
        &after.agents,
        codec::agent_record,
    )
    .await?;
    sync_model(
        connection,
        schema,
        "agentCapabilityGrant",
        &before.grants,
        &after.grants,
        codec::grant_record,
    )
    .await?;
    sync_model(
        connection,
        schema,
        "approvalRequest",
        &before.approvals,
        &after.approvals,
        codec::approval_record,
    )
    .await?;
    delete_missing(
        connection,
        schema,
        "approvalRequest",
        &before.approvals,
        &after.approvals,
    )
    .await?;
    delete_missing(
        connection,
        schema,
        "agentCapabilityGrant",
        &before.grants,
        &after.grants,
    )
    .await?;
    delete_missing(connection, schema, "agent", &before.agents, &after.agents).await?;
    delete_missing(connection, schema, "agentHost", &before.hosts, &after.hosts).await?;
    Ok(())
}

async fn sync_model<T: PartialEq>(
    connection: &mut MySqlConnection,
    schema: &super::super::schema::MySqlSchema,
    model: &str,
    before: &HashMap<String, T>,
    after: &HashMap<String, T>,
    encode: fn(&T) -> Result<Map<String, Value>, AuthError>,
) -> Result<(), AuthError> {
    insert_missing(connection, schema, model, before, after, encode).await?;
    update_changed(connection, schema, model, before, after, encode).await
}

async fn load<T>(
    connection: &mut MySqlConnection,
    schema: &super::super::schema::MySqlSchema,
    model: &str,
    decode: fn(Map<String, Value>) -> Result<T, AuthError>,
) -> Result<HashMap<String, T>, AuthError> {
    execute::find_many_for_update(
        connection,
        schema,
        model,
        &[],
        &MySqlFindOptions::default(),
    )
    .await?
    .into_iter()
    .map(|row| {
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Storage(format!("invalid MySQL {model} row: id")))?
            .to_owned();
        Ok((id, decode(row)?))
    })
    .collect()
}

async fn delete_missing<T>(
    connection: &mut MySqlConnection,
    schema: &super::super::schema::MySqlSchema,
    model: &str,
    before: &HashMap<String, T>,
    after: &HashMap<String, T>,
) -> Result<(), AuthError> {
    for id in before.keys().filter(|id| !after.contains_key(*id)) {
        execute::delete_many(
            connection,
            schema,
            model,
            &[MySqlFilter::equal("id", json!(id))],
        )
        .await?;
    }
    Ok(())
}

async fn insert_missing<T>(
    connection: &mut MySqlConnection,
    schema: &super::super::schema::MySqlSchema,
    model: &str,
    before: &HashMap<String, T>,
    after: &HashMap<String, T>,
    encode: fn(&T) -> Result<Map<String, Value>, AuthError>,
) -> Result<(), AuthError> {
    for (id, value) in after {
        if !before.contains_key(id) {
            execute::insert_required(connection, schema, model, encode(value)?).await?;
        }
    }
    Ok(())
}

async fn update_changed<T: PartialEq>(
    connection: &mut MySqlConnection,
    schema: &super::super::schema::MySqlSchema,
    model: &str,
    before: &HashMap<String, T>,
    after: &HashMap<String, T>,
    encode: fn(&T) -> Result<Map<String, Value>, AuthError>,
) -> Result<(), AuthError> {
    for (id, value) in after {
        if before.get(id).is_some_and(|previous| previous != value) {
            let mut values = encode(value)?;
            values.remove("id");
            execute::update_one(
                connection,
                schema,
                model,
                &[MySqlFilter::equal("id", json!(id))],
                values,
            )
            .await?
            .ok_or_else(|| {
                AuthError::Storage(format!("MySQL {model} row disappeared during update"))
            })?;
        }
    }
    Ok(())
}

fn storage(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
