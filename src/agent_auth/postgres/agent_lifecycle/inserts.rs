use crate::{
    AuthError,
    agent_auth::{AgentApprovalRequest, AgentCapabilityGrant, AgentHost, AgentIdentity},
};
use sqlx::{Postgres, Transaction};

use super::super::{PostgresAgentAuthStore, query, rows, storage_error};

pub(super) async fn host(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    value: &AgentHost,
) -> Result<(), AuthError> {
    let model = store.model("agentHost")?;
    query::insert(&model, rows::host_writes(&model, value)?)
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(())
}

pub(super) async fn agent(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    value: &AgentIdentity,
) -> Result<(), AuthError> {
    let model = store.model("agent")?;
    query::insert(&model, rows::agent_writes(&model, value)?)
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(())
}

pub(super) async fn grant(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    value: &AgentCapabilityGrant,
) -> Result<(), AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    query::insert(&model, rows::grant_writes(&model, value)?)
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(())
}

pub(super) async fn approval(
    transaction: &mut Transaction<'_, Postgres>,
    store: &PostgresAgentAuthStore,
    value: &AgentApprovalRequest,
) -> Result<(), AuthError> {
    let model = store.model("approvalRequest")?;
    query::insert(&model, rows::approval_writes(&model, value)?)
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(())
}
