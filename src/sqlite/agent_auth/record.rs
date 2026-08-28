use super::codec;
pub(super) use super::codec::{
    decode_agent, decode_approval, decode_grant, decode_host, millis, normalize_agent,
    normalize_approval, normalize_grant, normalize_host, normalize_plan,
};
use crate::{
    AuthError,
    agent_auth::AgentAuthSnapshot,
    sqlite::{SqliteFilter, SqliteFindOptions, SqliteStore, query::execute},
};
use serde_json::{Map, Value, json};
use sqlx::{SqliteConnection, pool::PoolConnection};
use std::collections::HashMap;

pub(super) async fn begin_immediate(
    store: &SqliteStore,
) -> Result<PoolConnection<sqlx::Sqlite>, AuthError> {
    let mut connection = store.pool.acquire().await.map_err(storage)?;
    sqlx::query("begin immediate")
        .execute(&mut *connection)
        .await
        .map_err(storage)?;
    Ok(connection)
}

pub(super) async fn commit(connection: &mut PoolConnection<sqlx::Sqlite>) -> Result<(), AuthError> {
    sqlx::query("commit")
        .execute(&mut **connection)
        .await
        .map(|_| ())
        .map_err(storage)
}

pub(super) async fn rollback(connection: &mut PoolConnection<sqlx::Sqlite>) {
    let _ = sqlx::query("rollback").execute(&mut **connection).await;
}

pub(super) async fn load_snapshot(
    store: &SqliteStore,
    connection: &mut SqliteConnection,
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
    store: &SqliteStore,
    connection: &mut SqliteConnection,
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
    connection: &mut SqliteConnection,
    schema: &super::super::schema::SqliteSchema,
    model: &str,
    before: &HashMap<String, T>,
    after: &HashMap<String, T>,
    encode: fn(&T) -> Result<Map<String, Value>, AuthError>,
) -> Result<(), AuthError> {
    insert_missing(connection, schema, model, before, after, encode).await?;
    update_changed(connection, schema, model, before, after, encode).await
}

async fn load<T>(
    connection: &mut SqliteConnection,
    schema: &super::super::schema::SqliteSchema,
    model: &str,
    decode: fn(Map<String, Value>) -> Result<T, AuthError>,
) -> Result<HashMap<String, T>, AuthError> {
    execute::find_many(
        connection,
        schema,
        model,
        &[],
        &SqliteFindOptions::default(),
    )
    .await?
    .into_iter()
    .map(|row| {
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Storage(format!("invalid SQLite {model} row: id")))?
            .to_owned();
        Ok((id, decode(row)?))
    })
    .collect()
}

async fn delete_missing<T>(
    connection: &mut SqliteConnection,
    schema: &super::super::schema::SqliteSchema,
    model: &str,
    before: &HashMap<String, T>,
    after: &HashMap<String, T>,
) -> Result<(), AuthError> {
    for id in before.keys().filter(|id| !after.contains_key(*id)) {
        execute::delete_many(
            connection,
            schema,
            model,
            &[SqliteFilter::equal("id", json!(id))],
        )
        .await?;
    }
    Ok(())
}

async fn insert_missing<T>(
    connection: &mut SqliteConnection,
    schema: &super::super::schema::SqliteSchema,
    model: &str,
    before: &HashMap<String, T>,
    after: &HashMap<String, T>,
    encode: fn(&T) -> Result<Map<String, Value>, AuthError>,
) -> Result<(), AuthError> {
    for (id, value) in after {
        if !before.contains_key(id) {
            execute::insert(connection, schema, model, encode(value)?).await?;
        }
    }
    Ok(())
}

async fn update_changed<T: PartialEq>(
    connection: &mut SqliteConnection,
    schema: &super::super::schema::SqliteSchema,
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
                &[SqliteFilter::equal("id", json!(id))],
                values,
            )
            .await?
            .ok_or_else(|| {
                AuthError::Storage(format!("SQLite {model} row disappeared during update"))
            })?;
        }
    }
    Ok(())
}

fn storage(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
