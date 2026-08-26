use super::{PostgresAgentAuthStore, is_unique_violation, query, rows, storage_error};
use crate::{
    AuthError,
    agent_auth::{
        AgentClaimedAutonomousAgent, AgentHost, AgentHostRotationOutcome, AgentHostStatus,
        AgentHostSwitchOutcome, AgentStatus,
    },
};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;

pub(super) async fn revoke_cascade(
    store: &PostgresAgentAuthStore,
    host_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AgentHost>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let Some(mut host) = lock_host(&mut transaction, store, "id", host_id).await? else {
        return Ok(None);
    };
    host.status = AgentHostStatus::Revoked;
    host.public_key = None;
    host.kid = None;
    host.jwks_url = None;
    host.updated_at = now;
    let host = write_host(&mut transaction, store, &host).await?;
    let agent_ids = revoke_agents(&mut transaction, store, host_id, now).await?;
    revoke_grants(&mut transaction, store, &agent_ids, now).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(Some(host))
}

pub(super) async fn switch_account_cascade(
    store: &PostgresAgentAuthStore,
    host_id: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AgentHostSwitchOutcome>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let Some(mut host) = lock_host(&mut transaction, store, "id", host_id).await? else {
        return Ok(None);
    };
    let previous_user_id = host.user_id.replace(user_id.to_owned());
    host.updated_at = now;
    let host = write_host(&mut transaction, store, &host).await?;
    let (claimed_agents, revoked_agent_ids) =
        switch_agents(&mut transaction, store, host_id, user_id, now).await?;
    let mut affected = claimed_agents
        .iter()
        .map(|claimed| claimed.agent.id.clone())
        .collect::<Vec<_>>();
    affected.extend(revoked_agent_ids.iter().cloned());
    revoke_grants(&mut transaction, store, &affected, now).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(Some(AgentHostSwitchOutcome {
        host,
        previous_user_id,
        revoked_agent_ids,
        claimed_agents,
    }))
}

pub(super) async fn rotate_key(
    store: &PostgresAgentAuthStore,
    old_id: &str,
    new_id: &str,
    public_key: String,
    kid: Option<String>,
    now: DateTime<Utc>,
) -> Result<AgentHostRotationOutcome, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let Some(mut host) = lock_host(&mut transaction, store, "id", old_id).await? else {
        return Ok(AgentHostRotationOutcome::NotFound);
    };
    if old_id != new_id
        && lock_host(&mut transaction, store, "id", new_id)
            .await?
            .is_some()
    {
        return Ok(AgentHostRotationOutcome::UniqueConflict);
    }
    host.public_key = Some(public_key);
    host.kid = kid;
    host.jwks_url = None;
    host.updated_at = now;
    if old_id == new_id {
        let host = write_host(&mut transaction, store, &host).await?;
        transaction.commit().await.map_err(storage_error)?;
        return Ok(AgentHostRotationOutcome::Rotated(Box::new(host)));
    }
    host.id = new_id.to_owned();
    match insert_host(&mut transaction, store, &host).await {
        Ok(()) => {}
        Err(error) if is_unique_violation(&error) => {
            return Ok(AgentHostRotationOutcome::UniqueConflict);
        }
        Err(error) => return Err(storage_error(error)),
    }
    move_host_references(&mut transaction, store, old_id, new_id, now).await?;
    let model = store.model("agentHost")?;
    sqlx::query(&format!(
        "DELETE FROM {} WHERE \"id\"=$1",
        model.quoted_table()
    ))
    .bind(old_id)
    .execute(&mut *transaction)
    .await
    .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AgentHostRotationOutcome::Rotated(Box::new(host)))
}

pub(super) async fn lock_host(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    field: &'static str,
    value: &str,
) -> Result<Option<AgentHost>, AuthError> {
    let model = store.model("agentHost")?;
    let mut query = query::filter(&model, [(field, serde_json::json!(value))])?;
    query.push(" FOR UPDATE LIMIT 1");
    query
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_host(&model, row))
        .transpose()
}

pub(super) async fn lock_other_public_key(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    public_key: &str,
    excluded_id: &str,
) -> Result<Option<AgentHost>, AuthError> {
    let model = store.model("agentHost")?;
    let sql = format!(
        "SELECT {} FROM {} WHERE {}=$1 AND \"id\"<>$2 FOR UPDATE LIMIT 1",
        model.all_projection(),
        model.quoted_table(),
        model.quoted_column("publicKey")?,
    );
    sqlx::query(&sql)
        .bind(public_key)
        .bind(excluded_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_host(&model, row))
        .transpose()
}

pub(super) async fn write_host(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    host: &AgentHost,
) -> Result<AgentHost, AuthError> {
    let model = store.model("agentHost")?;
    let mut query = query::update(&model, rows::host_writes(&model, host)?, &host.id)?;
    query.push(" RETURNING ").push(model.all_projection());
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    rows::decode_host(&model, &row)
}

async fn insert_host(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    host: &AgentHost,
) -> Result<(), sqlx::Error> {
    let model = store
        .model("agentHost")
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    let writes = rows::host_writes(&model, host)
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    query::insert(&model, writes)
        .build()
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn revoke_agents(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    host_id: &str,
    now: DateTime<Utc>,
) -> Result<Vec<String>, AuthError> {
    let model = store.model("agent")?;
    sqlx::query_scalar::<_, String>(&format!(
        "UPDATE {} SET {}='revoked', {}='', {}=NULL, {}=NULL, {}=$2 WHERE {}=$1 RETURNING \"id\"",
        model.quoted_table(),
        model.quoted_column("status")?,
        model.quoted_column("publicKey")?,
        model.quoted_column("kid")?,
        model.quoted_column("jwksUrl")?,
        model.quoted_column("updatedAt")?,
        model.quoted_column("hostId")?,
    ))
    .bind(host_id)
    .bind(now)
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)
}

async fn switch_agents(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    host_id: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<(Vec<AgentClaimedAutonomousAgent>, Vec<String>), AuthError> {
    let model = store.model("agent")?;
    let mut claimed_agents = lock_claimable_agents(transaction, store, host_id).await?;
    let mut update = sqlx::QueryBuilder::new("UPDATE ");
    update
        .push(model.quoted_table())
        .push(" SET ")
        .push(model.quoted_column("status")?)
        .push("='claimed', ")
        .push(model.quoted_column("userId")?)
        .push("=");
    model
        .encode("userId", serde_json::json!(user_id))?
        .push_bind(&mut update);
    update
        .push(", ")
        .push(model.quoted_column("updatedAt")?)
        .push("=")
        .push_bind(now)
        .push(" WHERE ")
        .push(model.quoted_column("hostId")?)
        .push("=")
        .push_bind(host_id.to_owned())
        .push(" AND ")
        .push(model.quoted_column("mode")?)
        .push("='autonomous' AND ")
        .push(model.quoted_column("status")?)
        .push("='active'");
    update
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    for claimed in &mut claimed_agents {
        claimed.agent.status = AgentStatus::Claimed;
        claimed.agent.user_id = Some(user_id.to_owned());
        claimed.agent.updated_at = now;
    }
    let revoked = sqlx::query_scalar::<_, String>(&format!(
        "UPDATE {} SET {}='revoked', {}='', {}=NULL, {}=NULL, {}=$2 WHERE {}=$1 AND {} NOT IN ('revoked','rejected','claimed') RETURNING \"id\"",
        model.quoted_table(), model.quoted_column("status")?, model.quoted_column("publicKey")?, model.quoted_column("kid")?,
        model.quoted_column("jwksUrl")?, model.quoted_column("updatedAt")?, model.quoted_column("hostId")?, model.quoted_column("status")?,
    ))
    .bind(host_id)
    .bind(now)
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)?;
    Ok((claimed_agents, revoked))
}

async fn lock_claimable_agents(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    host_id: &str,
) -> Result<Vec<AgentClaimedAutonomousAgent>, AuthError> {
    let agents = store.model("agent")?;
    let rows = sqlx::query(&format!(
        "SELECT {} FROM {} WHERE {}=$1 AND {}='autonomous' AND {}='active' ORDER BY {},\"id\" FOR UPDATE",
        agents.all_projection(),
        agents.quoted_table(),
        agents.quoted_column("hostId")?,
        agents.quoted_column("mode")?,
        agents.quoted_column("status")?,
        agents.quoted_column("createdAt")?,
    ))
    .bind(host_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)?;
    let identities = rows
        .iter()
        .map(|row| rows::decode_agent(&agents, row))
        .collect::<Result<Vec<_>, _>>()?;
    let ids = identities
        .iter()
        .map(|agent: &crate::AgentIdentity| agent.id.clone())
        .collect::<Vec<_>>();
    let mut capabilities = BTreeMap::<String, Vec<String>>::new();
    if !ids.is_empty() {
        let grants = store.model("agentCapabilityGrant")?;
        for row in sqlx::query(&format!(
            "SELECT {} AS \"agentId\",{} AS \"capability\" FROM {} WHERE {}=ANY($1) AND {}='active' ORDER BY {},\"id\"",
            grants.quoted_column("agentId")?,
            grants.quoted_column("capability")?,
            grants.quoted_table(),
            grants.quoted_column("agentId")?,
            grants.quoted_column("status")?,
            grants.quoted_column("createdAt")?,
        ))
        .bind(&ids)
        .fetch_all(&mut **transaction)
        .await
        .map_err(storage_error)?
        {
            let agent_id = row.try_get::<String, _>("agentId").map_err(storage_error)?;
            let capability = row
                .try_get::<String, _>("capability")
                .map_err(storage_error)?;
            capabilities.entry(agent_id).or_default().push(capability);
        }
    }
    Ok(identities
        .into_iter()
        .map(|agent| AgentClaimedAutonomousAgent {
            capabilities: capabilities.remove(&agent.id).unwrap_or_default(),
            agent,
        })
        .collect())
}

async fn revoke_grants(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    agent_ids: &[String],
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    if agent_ids.is_empty() {
        return Ok(());
    }
    let model = store.model("agentCapabilityGrant")?;
    sqlx::query(&format!(
        "UPDATE {} SET {}='revoked', {}=$2 WHERE {}=ANY($1)",
        model.quoted_table(),
        model.quoted_column("status")?,
        model.quoted_column("updatedAt")?,
        model.quoted_column("agentId")?,
    ))
    .bind(agent_ids)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    Ok(())
}

async fn move_host_references(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    old_id: &str,
    new_id: &str,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let model = store.model("agent")?;
    sqlx::query(&format!(
        "UPDATE {} SET {}=$2, {}=$3 WHERE {}=$1",
        model.quoted_table(),
        model.quoted_column("hostId")?,
        model.quoted_column("updatedAt")?,
        model.quoted_column("hostId")?,
    ))
    .bind(old_id)
    .bind(new_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    let approvals = store.model("approvalRequest")?;
    sqlx::query(&format!(
        "UPDATE {} SET {}=$2, {}=$3 WHERE {}=$1",
        approvals.quoted_table(),
        approvals.quoted_column("hostId")?,
        approvals.quoted_column("updatedAt")?,
        approvals.quoted_column("hostId")?,
    ))
    .bind(old_id)
    .bind(new_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    Ok(())
}
