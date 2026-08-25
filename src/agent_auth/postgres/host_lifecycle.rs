use super::{
    PostgresAgentAuthStore, is_unique_violation, query,
    rows::{AGENT_FIELDS, AgentRow, HOST_FIELDS, HostRow, encode_json},
    storage_error,
};
use crate::{
    AuthError,
    agent_auth::{
        AgentClaimedAutonomousAgent, AgentHost, AgentHostRotationOutcome, AgentHostStatus,
        AgentHostSwitchOutcome, AgentStatus, schema::AgentAuthModel,
    },
};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

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
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<AgentHostSwitchOutcome>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let Some(mut host) = lock_host(&mut transaction, store, "id", host_id).await? else {
        return Ok(None);
    };
    let previous_user_id = host.user_id.replace(user_id);
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
    let model = store.schema.model(AgentAuthModel::AgentHost);
    sqlx::query(&format!("DELETE FROM {} WHERE \"id\"=$1", model.table()))
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
    field: &str,
    value: &str,
) -> Result<Option<AgentHost>, AuthError> {
    sqlx::query_as::<_, HostRow>(&query::select(
        &store.schema,
        AgentAuthModel::AgentHost,
        HOST_FIELDS,
        &[field],
        " FOR UPDATE LIMIT 1",
    ))
    .bind(value)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(storage_error)?
    .map(TryInto::try_into)
    .transpose()
}

pub(super) async fn lock_other_public_key(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    public_key: &str,
    excluded_id: &str,
) -> Result<Option<AgentHost>, AuthError> {
    let model = store.schema.model(AgentAuthModel::AgentHost);
    let sql = format!(
        "SELECT {} FROM {} WHERE {}=$1 AND \"id\"<>$2 FOR UPDATE LIMIT 1",
        model.projection(HOST_FIELDS),
        model.table(),
        model.column("publicKey"),
    );
    sqlx::query_as::<_, HostRow>(&sql)
        .bind(public_key)
        .bind(excluded_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?
        .map(TryInto::try_into)
        .transpose()
}

pub(super) async fn write_host(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    host: &AgentHost,
) -> Result<AgentHost, AuthError> {
    let capabilities = encode_json(&host.default_capabilities)?;
    sqlx::query_as::<_, HostRow>(&query::update(
        &store.schema,
        AgentAuthModel::AgentHost,
        HOST_FIELDS,
    ))
    .bind(&host.id)
    .bind(&host.name)
    .bind(host.user_id)
    .bind(capabilities)
    .bind(&host.public_key)
    .bind(&host.kid)
    .bind(&host.jwks_url)
    .bind(&host.enrollment_token_hash)
    .bind(host.enrollment_token_expires_at)
    .bind(host.status.as_str())
    .bind(host.activated_at)
    .bind(host.expires_at)
    .bind(host.last_used_at)
    .bind(host.created_at)
    .bind(host.updated_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)?
    .try_into()
}

async fn insert_host(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    host: &AgentHost,
) -> Result<(), sqlx::Error> {
    let capabilities = serde_json::to_string(&host.default_capabilities)
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
    sqlx::query(&query::insert(
        &store.schema,
        AgentAuthModel::AgentHost,
        HOST_FIELDS,
    ))
    .bind(&host.id)
    .bind(&host.name)
    .bind(host.user_id)
    .bind(capabilities)
    .bind(&host.public_key)
    .bind(&host.kid)
    .bind(&host.jwks_url)
    .bind(&host.enrollment_token_hash)
    .bind(host.enrollment_token_expires_at)
    .bind(host.status.as_str())
    .bind(host.activated_at)
    .bind(host.expires_at)
    .bind(host.last_used_at)
    .bind(host.created_at)
    .bind(host.updated_at)
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
    let model = store.schema.model(AgentAuthModel::Agent);
    sqlx::query_scalar::<_, String>(&format!(
        "UPDATE {} SET {}='revoked', {}='', {}=NULL, {}=NULL, {}=$2 WHERE {}=$1 RETURNING \"id\"",
        model.table(),
        model.column("status"),
        model.column("publicKey"),
        model.column("kid"),
        model.column("jwksUrl"),
        model.column("updatedAt"),
        model.column("hostId"),
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
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(Vec<AgentClaimedAutonomousAgent>, Vec<String>), AuthError> {
    let model = store.schema.model(AgentAuthModel::Agent);
    let mut claimed_agents = lock_claimable_agents(transaction, store, host_id).await?;
    sqlx::query(&format!(
        "UPDATE {} SET {}='claimed', {}=$2, {}=$3 WHERE {}=$1 AND {}='autonomous' AND {}='active'",
        model.table(),
        model.column("status"),
        model.column("userId"),
        model.column("updatedAt"),
        model.column("hostId"),
        model.column("mode"),
        model.column("status"),
    ))
    .bind(host_id)
    .bind(user_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    for claimed in &mut claimed_agents {
        claimed.agent.status = AgentStatus::Claimed;
        claimed.agent.user_id = Some(user_id);
        claimed.agent.updated_at = now;
    }
    let revoked = sqlx::query_scalar::<_, String>(&format!(
        "UPDATE {} SET {}='revoked', {}='', {}=NULL, {}=NULL, {}=$2 WHERE {}=$1 AND {} NOT IN ('revoked','rejected','claimed') RETURNING \"id\"",
        model.table(), model.column("status"), model.column("publicKey"), model.column("kid"),
        model.column("jwksUrl"), model.column("updatedAt"), model.column("hostId"), model.column("status"),
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
    let agents = store.schema.model(AgentAuthModel::Agent);
    let rows = sqlx::query_as::<_, AgentRow>(&format!(
        "SELECT {} FROM {} WHERE {}=$1 AND {}='autonomous' AND {}='active' ORDER BY {},\"id\" FOR UPDATE",
        agents.projection(AGENT_FIELDS),
        agents.table(),
        agents.column("hostId"),
        agents.column("mode"),
        agents.column("status"),
        agents.column("createdAt"),
    ))
    .bind(host_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)?;
    let identities = rows
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<_>, _>>()?;
    let ids = identities
        .iter()
        .map(|agent: &crate::AgentIdentity| agent.id.clone())
        .collect::<Vec<_>>();
    let mut capabilities = BTreeMap::<String, Vec<String>>::new();
    if !ids.is_empty() {
        let grants = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
        for (agent_id, capability) in sqlx::query_as::<_, (String, String)>(&format!(
            "SELECT {},{} FROM {} WHERE {}=ANY($1) AND {}='active' ORDER BY {},\"id\"",
            grants.column("agentId"),
            grants.column("capability"),
            grants.table(),
            grants.column("agentId"),
            grants.column("status"),
            grants.column("createdAt"),
        ))
        .bind(&ids)
        .fetch_all(&mut **transaction)
        .await
        .map_err(storage_error)?
        {
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
    let model = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
    sqlx::query(&format!(
        "UPDATE {} SET {}='revoked', {}=$2 WHERE {}=ANY($1)",
        model.table(),
        model.column("status"),
        model.column("updatedAt"),
        model.column("agentId"),
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
    let model = store.schema.model(AgentAuthModel::Agent);
    sqlx::query(&format!(
        "UPDATE {} SET {}=$2, {}=$3 WHERE {}=$1",
        model.table(),
        model.column("hostId"),
        model.column("updatedAt"),
        model.column("hostId"),
    ))
    .bind(old_id)
    .bind(new_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    let approvals = store.schema.model(AgentAuthModel::ApprovalRequest);
    sqlx::query(&format!(
        "UPDATE {} SET {}=$2, {}=$3 WHERE {}=$1",
        approvals.table(),
        approvals.column("hostId"),
        approvals.column("updatedAt"),
        approvals.column("hostId"),
    ))
    .bind(old_id)
    .bind(new_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    Ok(())
}
