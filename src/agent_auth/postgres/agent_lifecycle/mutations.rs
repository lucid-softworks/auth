use crate::{
    AuthError,
    agent_auth::{
        AgentCleanupOutcome, AgentGrantStatus, AgentIdentity, AgentKeyRotationOutcome,
        AgentRevocationOutcome, AgentStatus,
    },
    postgres::PostgresModel,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use super::{
    super::{PostgresAgentAuthStore, lock_creation, query, rows, storage_error},
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
    let grant = store.model("agentCapabilityGrant")?;
    let mut query = QueryBuilder::new("UPDATE ");
    query
        .push(grant.quoted_table())
        .push(" SET ")
        .push(grant.quoted_column("status")?)
        .push(" = ");
    grant
        .encode("status", json!(AgentGrantStatus::Revoked.as_str()))?
        .push_bind(&mut query);
    query
        .push(", ")
        .push(grant.quoted_column("updatedAt")?)
        .push(" = ");
    grant
        .encode("updatedAt", json!(now.to_rfc3339()))?
        .push_bind(&mut query);
    query
        .push(" WHERE ")
        .push(grant.quoted_column("agentId")?)
        .push(" = ");
    grant
        .encode("agentId", json!(agent_id))?
        .push_bind(&mut query);
    let result = query
        .build()
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
    transaction: &mut Transaction<'_, Postgres>,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AgentIdentity>, AuthError> {
    let model = store.model("agent")?;
    let mut query = QueryBuilder::new("UPDATE ");
    query.push(model.quoted_table()).push(" SET ");
    for (index, (field, value)) in [
        ("status", json!(AgentStatus::Revoked.as_str())),
        ("publicKey", json!("")),
        ("kid", Value::Null),
        ("updatedAt", json!(now.to_rfc3339())),
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            query.push(", ");
        }
        query.push(model.quoted_column(field)?).push(" = ");
        model.encode(field, value)?.push_bind(&mut query);
    }
    query.push(" WHERE \"id\" = ");
    model.encode("id", json!(agent_id))?.push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    query
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_agent(&model, row))
        .transpose()
}

pub(in crate::agent_auth::postgres) async fn reactivate(
    store: &PostgresAgentAuthStore,
    agent: AgentIdentity,
    grants: Vec<crate::AgentCapabilityGrant>,
) -> Result<Option<AgentIdentity>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let model = store.model("agent")?;
    if !lock_agent(&model, &mut transaction, &agent.id).await? {
        return Ok(None);
    }
    replace_grants(store, &mut transaction, &agent.id, &grants).await?;
    let agent = update_agent(store, &mut transaction, &agent).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(Some(agent))
}

async fn replace_grants(
    store: &PostgresAgentAuthStore,
    transaction: &mut Transaction<'_, Postgres>,
    agent_id: &str,
    grants: &[crate::AgentCapabilityGrant],
) -> Result<(), AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let mut delete = QueryBuilder::new("DELETE FROM ");
    delete
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("agentId")?)
        .push(" = ");
    model
        .encode("agentId", json!(agent_id))?
        .push_bind(&mut delete);
    delete
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    for grant in grants {
        inserts::grant(transaction, store, grant).await?;
    }
    Ok(())
}

async fn update_agent(
    store: &PostgresAgentAuthStore,
    transaction: &mut Transaction<'_, Postgres>,
    agent: &AgentIdentity,
) -> Result<AgentIdentity, AuthError> {
    let model = store.model("agent")?;
    let mut query = query::update(&model, rows::agent_writes(&model, agent)?, &agent.id)?;
    query.push(" RETURNING ").push(model.all_projection());
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    rows::decode_agent(&model, &row)
}

pub(in crate::agent_auth::postgres) async fn cleanup(
    store: &PostgresAgentAuthStore,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<AgentCleanupOutcome, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let agent_ids = cleanup_model(
        &store.model("agent")?,
        &mut transaction,
        user_id,
        now,
        AgentStatus::Active.as_str(),
        AgentStatus::Expired.as_str(),
    )
    .await?;
    let approval_ids = cleanup_model(
        &store.model("approvalRequest")?,
        &mut transaction,
        user_id,
        now,
        crate::agent_auth::AgentApprovalStatus::Pending.as_str(),
        crate::agent_auth::AgentApprovalStatus::Expired.as_str(),
    )
    .await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AgentCleanupOutcome {
        agent_ids,
        approval_ids,
    })
}

async fn cleanup_model(
    model: &PostgresModel<'_>,
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    now: DateTime<Utc>,
    current_status: &str,
    next_status: &str,
) -> Result<Vec<String>, AuthError> {
    let mut query = QueryBuilder::new("UPDATE ");
    query
        .push(model.quoted_table())
        .push(" SET ")
        .push(model.quoted_column("status")?)
        .push(" = ");
    model
        .encode("status", json!(next_status))?
        .push_bind(&mut query);
    query
        .push(", ")
        .push(model.quoted_column("updatedAt")?)
        .push(" = ");
    model
        .encode("updatedAt", json!(now.to_rfc3339()))?
        .push_bind(&mut query);
    query
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    model
        .encode("userId", json!(user_id.to_string()))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("status")?)
        .push(" = ");
    model
        .encode("status", json!(current_status))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("expiresAt")?)
        .push(" IS NOT NULL AND ")
        .push(model.quoted_column("expiresAt")?)
        .push(" <= ");
    model
        .encode("expiresAt", json!(now.to_rfc3339()))?
        .push_bind(&mut query);
    query.push(" RETURNING \"id\"");
    query
        .build_query_scalar()
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
    let model = store.model("agent")?;
    if !lock_agent(&model, &mut transaction, agent_id).await? {
        return Ok(AgentKeyRotationOutcome::NotFound);
    }
    if rotation_conflicts(&model, &mut transaction, agent_id, &public_key, &kid).await? {
        return Ok(AgentKeyRotationOutcome::UniqueConflict);
    }
    let agent = update_key(&model, &mut transaction, agent_id, &public_key, &kid, now).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AgentKeyRotationOutcome::Rotated(Box::new(agent)))
}

async fn lock_agent(
    model: &PostgresModel<'_>,
    transaction: &mut Transaction<'_, Postgres>,
    agent_id: &str,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT \"id\" FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model.encode("id", json!(agent_id))?.push_bind(&mut query);
    query.push(" FOR UPDATE");
    Ok(query
        .build_query_scalar::<String>()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?
        .is_some())
}

async fn rotation_conflicts(
    model: &PostgresModel<'_>,
    transaction: &mut Transaction<'_, Postgres>,
    agent_id: &str,
    public_key: &str,
    kid: &Option<String>,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" <> ");
    model.encode("id", json!(agent_id))?.push_bind(&mut query);
    query
        .push(" AND (")
        .push(model.quoted_column("publicKey")?)
        .push(" = ");
    model
        .encode("publicKey", json!(public_key))?
        .push_bind(&mut query);
    query.push(" OR (");
    model
        .encode("kid", kid.clone().map_or(Value::Null, Value::String))?
        .push_bind(&mut query);
    query
        .push(" IS NOT NULL AND ")
        .push(model.quoted_column("kid")?)
        .push(" = ");
    model
        .encode("kid", kid.clone().map_or(Value::Null, Value::String))?
        .push_bind(&mut query);
    query.push(")))");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

async fn update_key(
    model: &PostgresModel<'_>,
    transaction: &mut Transaction<'_, Postgres>,
    agent_id: &str,
    public_key: &str,
    kid: &Option<String>,
    now: DateTime<Utc>,
) -> Result<AgentIdentity, AuthError> {
    let mut query = QueryBuilder::new("UPDATE ");
    query.push(model.quoted_table()).push(" SET ");
    for (index, (field, value)) in [
        ("publicKey", json!(public_key)),
        ("kid", kid.clone().map_or(Value::Null, Value::String)),
        ("updatedAt", json!(now.to_rfc3339())),
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            query.push(", ");
        }
        query.push(model.quoted_column(field)?).push(" = ");
        model.encode(field, value)?.push_bind(&mut query);
    }
    query.push(" WHERE \"id\" = ");
    model.encode("id", json!(agent_id))?.push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    rows::decode_agent(model, &row)
}
