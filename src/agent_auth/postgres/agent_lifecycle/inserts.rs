use crate::{
    AuthError,
    agent_auth::{
        AgentApprovalRequest, AgentCapabilityGrant, AgentHost, AgentIdentity,
        schema::{AgentAuthModel, ResolvedAgentAuthSchema},
    },
};
use sqlx::{Postgres, Transaction};

use super::super::{
    query,
    rows::{
        AGENT_FIELDS, APPROVAL_FIELDS, GRANT_FIELDS, HOST_FIELDS, encode_json, encode_optional_json,
    },
    storage_error,
};

pub(super) async fn host(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &ResolvedAgentAuthSchema,
    host: &AgentHost,
) -> Result<(), AuthError> {
    let capabilities = encode_json(&host.default_capabilities)?;
    sqlx::query(&query::insert(
        schema,
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
    .await
    .map_err(storage_error)?;
    Ok(())
}

pub(super) async fn agent(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &ResolvedAgentAuthSchema,
    agent: &AgentIdentity,
) -> Result<(), AuthError> {
    let metadata = encode_optional_json(&agent.metadata)?;
    sqlx::query(&query::insert(schema, AgentAuthModel::Agent, AGENT_FIELDS))
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
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(())
}

pub(super) async fn grant(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &ResolvedAgentAuthSchema,
    grant: &AgentCapabilityGrant,
) -> Result<(), AuthError> {
    let constraints = encode_optional_json(&grant.constraints)?;
    sqlx::query(&query::insert(
        schema,
        AgentAuthModel::AgentCapabilityGrant,
        GRANT_FIELDS,
    ))
    .bind(&grant.id)
    .bind(&grant.agent_id)
    .bind(&grant.capability)
    .bind(constraints)
    .bind(grant.denied_by)
    .bind(grant.granted_by)
    .bind(grant.expires_at)
    .bind(grant.status.as_str())
    .bind(&grant.reason)
    .bind(grant.created_at)
    .bind(grant.updated_at)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    Ok(())
}

pub(super) async fn approval(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &ResolvedAgentAuthSchema,
    approval: &AgentApprovalRequest,
) -> Result<(), AuthError> {
    sqlx::query(&query::insert(
        schema,
        AgentAuthModel::ApprovalRequest,
        APPROVAL_FIELDS,
    ))
    .bind(&approval.id)
    .bind(approval.method.as_str())
    .bind(&approval.agent_id)
    .bind(&approval.host_id)
    .bind(approval.user_id)
    .bind(&approval.capabilities)
    .bind(approval.status.as_str())
    .bind(&approval.user_code_hash)
    .bind(&approval.login_hint)
    .bind(&approval.binding_message)
    .bind(&approval.client_notification_token)
    .bind(&approval.client_notification_endpoint)
    .bind(&approval.delivery_mode)
    .bind(approval.interval)
    .bind(approval.last_polled_at)
    .bind(approval.expires_at)
    .bind(approval.created_at)
    .bind(approval.updated_at)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    Ok(())
}
