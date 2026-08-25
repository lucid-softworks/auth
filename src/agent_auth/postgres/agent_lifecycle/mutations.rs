use crate::{
    AuthError,
    agent_auth::{
        AgentCleanupOutcome, AgentGrantStatus, AgentIdentity, AgentKeyRotationOutcome,
        AgentRevocationOutcome, AgentStatus, schema::AgentAuthModel,
    },
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{
    super::{
        PostgresAgentAuthStore, lock_creation, query,
        rows::{AGENT_FIELDS, AgentRow, encode_optional_json},
        storage_error,
    },
    inserts,
};

pub(in crate::agent_auth::postgres) async fn revoke(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AgentRevocationOutcome>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let Some(agent) = revoke_agent(store, &mut transaction, agent_id, now).await? else {
        return Ok(None);
    };
    let grant = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
    let result = sqlx::query(&format!(
        "UPDATE {} SET {}=$2, {}=$3 WHERE {}=$1",
        grant.table(),
        grant.column("status"),
        grant.column("updatedAt"),
        grant.column("agentId"),
    ))
    .bind(agent_id)
    .bind(AgentGrantStatus::Revoked.as_str())
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(Some(AgentRevocationOutcome {
        agent,
        grants_revoked: result.rows_affected() as usize,
    }))
}

async fn revoke_agent(
    store: &PostgresAgentAuthStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AgentIdentity>, AuthError> {
    let model = store.schema.model(AgentAuthModel::Agent);
    let sql = format!(
        "UPDATE {} SET {}=$2, {}=$3, {}=$4, {}=$5 WHERE {}=$1 RETURNING {}",
        model.table(),
        model.column("status"),
        model.column("publicKey"),
        model.column("kid"),
        model.column("updatedAt"),
        model.column("id"),
        model.projection(AGENT_FIELDS),
    );
    sqlx::query_as::<_, AgentRow>(&sql)
        .bind(agent_id)
        .bind(AgentStatus::Revoked.as_str())
        .bind("")
        .bind(None::<String>)
        .bind(now)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?
        .map(TryInto::try_into)
        .transpose()
}

pub(in crate::agent_auth::postgres) async fn reactivate(
    store: &PostgresAgentAuthStore,
    agent: AgentIdentity,
    grants: Vec<crate::AgentCapabilityGrant>,
) -> Result<Option<AgentIdentity>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let model = store.schema.model(AgentAuthModel::Agent);
    let found = sqlx::query_scalar::<_, String>(&format!(
        "SELECT {} FROM {} WHERE {}=$1 FOR UPDATE",
        model.column("id"),
        model.table(),
        model.column("id"),
    ))
    .bind(&agent.id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if found.is_none() {
        return Ok(None);
    }
    replace_grants(store, &mut transaction, &agent.id, &grants).await?;
    let agent = update_agent(store, &mut transaction, &agent).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(Some(agent))
}

async fn replace_grants(
    store: &PostgresAgentAuthStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent_id: &str,
    grants: &[crate::AgentCapabilityGrant],
) -> Result<(), AuthError> {
    let model = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
    sqlx::query(&format!(
        "DELETE FROM {} WHERE {}=$1",
        model.table(),
        model.column("agentId"),
    ))
    .bind(agent_id)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    for grant in grants {
        inserts::grant(transaction, &store.schema, grant).await?;
    }
    Ok(())
}

async fn update_agent(
    store: &PostgresAgentAuthStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent: &AgentIdentity,
) -> Result<AgentIdentity, AuthError> {
    let metadata = encode_optional_json(&agent.metadata)?;
    let row = sqlx::query_as::<_, AgentRow>(&query::update(
        &store.schema,
        AgentAuthModel::Agent,
        AGENT_FIELDS,
    ))
    .bind(&agent.id)
    .bind(&agent.name)
    .bind(agent.user_id)
    .bind(&agent.host_id)
    .bind(agent.status.as_str())
    .bind(agent.mode.as_str())
    .bind(&agent.public_key)
    .bind(&agent.kid)
    .bind(&agent.jwks_url)
    .bind(agent.last_used_at)
    .bind(agent.activated_at)
    .bind(agent.expires_at)
    .bind(metadata)
    .bind(agent.created_at)
    .bind(agent.updated_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)?;
    row.try_into()
}

pub(in crate::agent_auth::postgres) async fn cleanup(
    store: &PostgresAgentAuthStore,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<AgentCleanupOutcome, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let agent_ids = cleanup_agents(store, &mut transaction, user_id, now).await?;
    let approval_ids = cleanup_approvals(store, &mut transaction, user_id, now).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AgentCleanupOutcome {
        agent_ids,
        approval_ids,
    })
}

async fn cleanup_agents(
    store: &PostgresAgentAuthStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Vec<String>, AuthError> {
    let model = store.schema.model(AgentAuthModel::Agent);
    sqlx::query_scalar(&format!(
        "UPDATE {} SET {}=$3, {}=$2 WHERE {}=$1 AND {}=$4 AND {} IS NOT NULL AND {} <= $2 RETURNING {}",
        model.table(),
        model.column("status"),
        model.column("updatedAt"),
        model.column("userId"),
        model.column("status"),
        model.column("expiresAt"),
        model.column("expiresAt"),
        model.column("id"),
    ))
    .bind(user_id)
    .bind(now)
    .bind(AgentStatus::Expired.as_str())
    .bind(AgentStatus::Active.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)
}

async fn cleanup_approvals(
    store: &PostgresAgentAuthStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Vec<String>, AuthError> {
    let model = store.schema.model(AgentAuthModel::ApprovalRequest);
    sqlx::query_scalar(&format!(
        "UPDATE {} SET {}=$3, {}=$2 WHERE {}=$1 AND {}=$4 AND {} <= $2 RETURNING {}",
        model.table(),
        model.column("status"),
        model.column("updatedAt"),
        model.column("userId"),
        model.column("status"),
        model.column("expiresAt"),
        model.column("id"),
    ))
    .bind(user_id)
    .bind(now)
    .bind(crate::agent_auth::AgentApprovalStatus::Expired.as_str())
    .bind(crate::agent_auth::AgentApprovalStatus::Pending.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)
}

pub(in crate::agent_auth::postgres) async fn rotate_key(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
    public_key: String,
    kid: Option<String>,
    now: DateTime<Utc>,
) -> Result<AgentKeyRotationOutcome, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "agent").await?;
    let model = store.schema.model(AgentAuthModel::Agent);
    let exists = lock_agent(model, &mut transaction, agent_id).await?;
    if !exists {
        return Ok(AgentKeyRotationOutcome::NotFound);
    }
    if rotation_conflicts(model, &mut transaction, agent_id, &public_key, &kid).await? {
        return Ok(AgentKeyRotationOutcome::UniqueConflict);
    }
    let agent = update_key(model, &mut transaction, agent_id, &public_key, &kid, now).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AgentKeyRotationOutcome::Rotated(Box::new(agent)))
}

async fn lock_agent(
    model: &crate::agent_auth::schema::ResolvedAgentAuthModel,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent_id: &str,
) -> Result<bool, AuthError> {
    Ok(sqlx::query_scalar::<_, String>(&format!(
        "SELECT {} FROM {} WHERE {}=$1 FOR UPDATE",
        model.column("id"),
        model.table(),
        model.column("id"),
    ))
    .bind(agent_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(storage_error)?
    .is_some())
}

async fn rotation_conflicts(
    model: &crate::agent_auth::schema::ResolvedAgentAuthModel,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent_id: &str,
    public_key: &str,
    kid: &Option<String>,
) -> Result<bool, AuthError> {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {}<>$1 AND ({}=$2 OR ($3::TEXT IS NOT NULL AND {}=$3)))",
        model.table(),
        model.column("id"),
        model.column("publicKey"),
        model.column("kid"),
    ))
    .bind(agent_id)
    .bind(public_key)
    .bind(kid)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)
}

async fn update_key(
    model: &crate::agent_auth::schema::ResolvedAgentAuthModel,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    agent_id: &str,
    public_key: &str,
    kid: &Option<String>,
    now: DateTime<Utc>,
) -> Result<AgentIdentity, AuthError> {
    let row = sqlx::query_as::<_, AgentRow>(&format!(
        "UPDATE {} SET {}=$2, {}=$3, {}=$4 WHERE {}=$1 RETURNING {}",
        model.table(),
        model.column("publicKey"),
        model.column("kid"),
        model.column("updatedAt"),
        model.column("id"),
        model.projection(AGENT_FIELDS),
    ))
    .bind(agent_id)
    .bind(public_key)
    .bind(kid)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)?;
    row.try_into()
}
