use super::{
    PostgresAgentAuthStore, is_unique_violation, query,
    rows::{
        AGENT_FIELDS, APPROVAL_FIELDS, AgentRow, ApprovalRow, GRANT_FIELDS, GrantRow, HOST_FIELDS,
        HostRow, encode_json, encode_optional_json,
    },
    storage_error,
};
use crate::{
    AuthError,
    agent_auth::{
        AgentApprovalRequest, AgentCapabilityGrant, AgentCapabilityTransitionPlan, AgentHost,
        AgentIdentity, schema::AgentAuthModel,
    },
};
use sqlx::{Postgres, Transaction};

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
        let model = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
        if sqlx::query(&format!("DELETE FROM {} WHERE \"id\"=$1", model.table()))
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(storage_error)?
            .rows_affected()
            != 1
        {
            return Ok(false);
        }
    }
    for grant in &plan.grants_to_update {
        if !update_grant(store, tx, grant).await? {
            return Ok(false);
        }
    }
    for grant in &plan.related_grants_to_update {
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
    let metadata = encode_optional_json(&value.metadata)?;
    Ok(sqlx::query_as::<_, AgentRow>(&query::update(
        &store.schema,
        AgentAuthModel::Agent,
        AGENT_FIELDS,
    ))
    .bind(&value.id)
    .bind(&value.name)
    .bind(value.user_id)
    .bind(&value.host_id)
    .bind(value.status.as_str())
    .bind(value.mode.as_str())
    .bind(&value.public_key)
    .bind(&value.kid)
    .bind(&value.jwks_url)
    .bind(value.last_used_at)
    .bind(value.activated_at)
    .bind(value.expires_at)
    .bind(metadata)
    .bind(value.created_at)
    .bind(value.updated_at)
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
    let capabilities = encode_json(&value.default_capabilities)?;
    Ok(sqlx::query_as::<_, HostRow>(&query::update(
        &store.schema,
        AgentAuthModel::AgentHost,
        HOST_FIELDS,
    ))
    .bind(&value.id)
    .bind(&value.name)
    .bind(value.user_id)
    .bind(capabilities)
    .bind(&value.public_key)
    .bind(&value.kid)
    .bind(&value.jwks_url)
    .bind(&value.enrollment_token_hash)
    .bind(value.enrollment_token_expires_at)
    .bind(value.status.as_str())
    .bind(value.activated_at)
    .bind(value.expires_at)
    .bind(value.last_used_at)
    .bind(value.created_at)
    .bind(value.updated_at)
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
    let constraints = encode_optional_json(&value.constraints)?;
    Ok(sqlx::query_as::<_, GrantRow>(&query::update(
        &store.schema,
        AgentAuthModel::AgentCapabilityGrant,
        GRANT_FIELDS,
    ))
    .bind(&value.id)
    .bind(&value.agent_id)
    .bind(&value.capability)
    .bind(constraints)
    .bind(value.denied_by)
    .bind(value.granted_by)
    .bind(value.expires_at)
    .bind(value.status.as_str())
    .bind(&value.reason)
    .bind(value.created_at)
    .bind(value.updated_at)
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
    let constraints = encode_optional_json(&value.constraints)?;
    let result = sqlx::query_as::<_, GrantRow>(&query::insert(
        &store.schema,
        AgentAuthModel::AgentCapabilityGrant,
        GRANT_FIELDS,
    ))
    .bind(&value.id)
    .bind(&value.agent_id)
    .bind(&value.capability)
    .bind(constraints)
    .bind(value.denied_by)
    .bind(value.granted_by)
    .bind(value.expires_at)
    .bind(value.status.as_str())
    .bind(&value.reason)
    .bind(value.created_at)
    .bind(value.updated_at)
    .fetch_one(&mut **tx)
    .await;
    match result {
        Ok(_) => Ok(true),
        Err(error) if is_unique_violation(&error) => Ok(false),
        Err(error) => Err(storage_error(error)),
    }
}

async fn update_approval(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    value: &AgentApprovalRequest,
) -> Result<bool, AuthError> {
    Ok(bind_approval(
        sqlx::query_as::<_, ApprovalRow>(&query::update(
            &store.schema,
            AgentAuthModel::ApprovalRequest,
            APPROVAL_FIELDS,
        )),
        value,
    )
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
    let result = bind_approval(
        sqlx::query_as::<_, ApprovalRow>(&query::insert(
            &store.schema,
            AgentAuthModel::ApprovalRequest,
            APPROVAL_FIELDS,
        )),
        value,
    )
    .fetch_one(&mut **tx)
    .await;
    match result {
        Ok(_) => Ok(true),
        Err(error) if is_unique_violation(&error) => Ok(false),
        Err(error) => Err(storage_error(error)),
    }
}

fn bind_approval<'q>(
    query: sqlx::query::QueryAs<'q, Postgres, ApprovalRow, sqlx::postgres::PgArguments>,
    value: &'q AgentApprovalRequest,
) -> sqlx::query::QueryAs<'q, Postgres, ApprovalRow, sqlx::postgres::PgArguments> {
    query
        .bind(&value.id)
        .bind(value.method.as_str())
        .bind(&value.agent_id)
        .bind(&value.host_id)
        .bind(value.user_id)
        .bind(&value.capabilities)
        .bind(value.status.as_str())
        .bind(&value.user_code_hash)
        .bind(&value.login_hint)
        .bind(&value.binding_message)
        .bind(&value.client_notification_token)
        .bind(&value.client_notification_endpoint)
        .bind(&value.delivery_mode)
        .bind(value.interval)
        .bind(value.last_polled_at)
        .bind(value.expires_at)
        .bind(value.created_at)
        .bind(value.updated_at)
}
