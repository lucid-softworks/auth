use super::{PostgresAgentAuthStore, is_unique_violation, query, rows, storage_error};
use crate::{
    AuthError,
    agent_auth::{
        AgentApprovalRequest, AgentCapabilityGrant, AgentCapabilityTransitionPlan, AgentHost,
        AgentIdentity,
    },
};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, Transaction};

pub(super) async fn apply(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    plan: &AgentCapabilityTransitionPlan,
) -> Result<bool, AuthError> {
    if let Some(agent) = &plan.agent_update
        && !update_agent(store, tx, agent).await?
    {
        return Ok(false);
    }
    for agent in &plan.related_agents_to_update {
        if !update_agent(store, tx, agent).await? {
            return Ok(false);
        }
    }
    if let Some(host) = &plan.host_update
        && !update_host(store, tx, host).await?
    {
        return Ok(false);
    }
    for id in &plan.grant_ids_to_delete {
        let model = store.model("agentCapabilityGrant")?;
        let mut query = QueryBuilder::new("DELETE FROM ");
        query.push(model.quoted_table()).push(" WHERE \"id\" = ");
        model.encode("id", json!(id))?.push_bind(&mut query);
        if query
            .build()
            .execute(&mut **tx)
            .await
            .map_err(storage_error)?
            .rows_affected()
            != 1
        {
            return Ok(false);
        }
    }
    for grant in plan
        .grants_to_update
        .iter()
        .chain(&plan.related_grants_to_update)
    {
        if !update_grant(store, tx, grant).await? {
            return Ok(false);
        }
    }
    for grant in &plan.grants_to_create {
        if !insert_grant(store, tx, grant).await? {
            return Ok(false);
        }
    }
    for approval in &plan.approvals_to_update {
        if !update_approval(store, tx, approval).await? {
            return Ok(false);
        }
    }
    if let Some(approval) = &plan.approval_to_create
        && !insert_approval(store, tx, approval).await?
    {
        return Ok(false);
    }
    Ok(true)
}

async fn update_agent(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    value: &AgentIdentity,
) -> Result<bool, AuthError> {
    let model = store.model("agent")?;
    let mut query = query::update(&model, rows::agent_writes(&model, value)?, &value.id)?;
    query.push(" RETURNING \"id\"");
    Ok(query
        .build_query_scalar::<String>()
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage_error)?
        .is_some())
}

async fn update_host(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    value: &AgentHost,
) -> Result<bool, AuthError> {
    let model = store.model("agentHost")?;
    let mut query = query::update(&model, rows::host_writes(&model, value)?, &value.id)?;
    query.push(" RETURNING \"id\"");
    Ok(query
        .build_query_scalar::<String>()
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage_error)?
        .is_some())
}

async fn update_grant(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    value: &AgentCapabilityGrant,
) -> Result<bool, AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let mut query = query::update(&model, rows::grant_writes(&model, value)?, &value.id)?;
    query.push(" RETURNING \"id\"");
    Ok(query
        .build_query_scalar::<String>()
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage_error)?
        .is_some())
}

async fn insert_grant(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    value: &AgentCapabilityGrant,
) -> Result<bool, AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let result = query::insert(&model, rows::grant_writes(&model, value)?)
        .build()
        .execute(&mut **tx)
        .await;
    classify_insert(result)
}

async fn update_approval(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    value: &AgentApprovalRequest,
) -> Result<bool, AuthError> {
    let model = store.model("approvalRequest")?;
    let mut query = query::update(&model, rows::approval_writes(&model, value)?, &value.id)?;
    query.push(" RETURNING \"id\"");
    Ok(query
        .build_query_scalar::<String>()
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage_error)?
        .is_some())
}

async fn insert_approval(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    value: &AgentApprovalRequest,
) -> Result<bool, AuthError> {
    let model = store.model("approvalRequest")?;
    let result = query::insert(&model, rows::approval_writes(&model, value)?)
        .build()
        .execute(&mut **tx)
        .await;
    classify_insert(result)
}

fn classify_insert(
    result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
) -> Result<bool, AuthError> {
    match result {
        Ok(_) => Ok(true),
        Err(error) if is_unique_violation(&error) => Ok(false),
        Err(error) => Err(storage_error(error)),
    }
}
