use super::{PostgresAgentAuthStore, query, rows, storage_error, transition_write};
use crate::{
    AuthError,
    agent_auth::{
        AgentApprovalStatus, AgentCapabilityTransitionOutcome, AgentCapabilityTransitionPlan,
        AgentCapabilityTransitionResult,
    },
};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, Transaction};

pub(super) async fn apply(
    store: &PostgresAgentAuthStore,
    plan: AgentCapabilityTransitionPlan,
) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
    let mut tx = store.pool().begin().await.map_err(storage_error)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key(&plan.expected_agent.host_id))
        .execute(&mut *tx)
        .await
        .map_err(storage_error)?;
    let Some(agent) = locked_agent(store, &mut tx, &plan.expected_agent.id).await? else {
        return Ok(AgentCapabilityTransitionOutcome::AgentNotFound);
    };
    let host = locked_host(store, &mut tx, &plan.expected_agent.host_id).await?;
    let mut grants = locked_grants(store, &mut tx, &plan.expected_agent.id).await?;
    let mut approvals = locked_pending_approvals(store, &mut tx, &plan.expected_agent.id).await?;
    let (mut related_agents, mut related_grants) = if plan.expected_related_agents.is_some() {
        let agents = locked_related_agents(store, &mut tx, &plan.expected_agent).await?;
        let grants = locked_related_grants(store, &mut tx, &agents).await?;
        (Some(agents), Some(grants))
    } else {
        (None, None)
    };
    let mut expected_grants = plan.expected_grants.clone();
    let mut expected_approvals = plan.expected_approvals.clone();
    let mut expected_related_agents = plan.expected_related_agents.clone();
    let mut expected_related_grants = plan.expected_related_grants.clone();
    sort_records(&mut grants, &mut approvals);
    sort_records(&mut expected_grants, &mut expected_approvals);
    sort_related(&mut related_agents, &mut related_grants);
    sort_related(&mut expected_related_agents, &mut expected_related_grants);
    if agent != plan.expected_agent
        || host != plan.expected_host
        || grants != expected_grants
        || approvals != expected_approvals
        || related_agents != expected_related_agents
        || related_grants != expected_related_grants
    {
        return Ok(AgentCapabilityTransitionOutcome::Conflict);
    }
    if !transition_write::apply(store, &mut tx, &plan).await? {
        return Ok(AgentCapabilityTransitionOutcome::Conflict);
    }
    tx.commit().await.map_err(storage_error)?;
    let agent = plan.agent_update.unwrap_or(plan.expected_agent);
    let host = plan.host_update.or(plan.expected_host);
    let grants = super::grant::list(store, &agent.id).await?;
    let approvals = super::approval::list_for_agent(store, &agent.id).await?;
    Ok(AgentCapabilityTransitionOutcome::Applied(Box::new(
        AgentCapabilityTransitionResult {
            agent,
            host,
            grants,
            approvals,
        },
    )))
}

fn lock_key(host_id: &str) -> String {
    format!("agent-capability-host:{host_id}")
}

async fn locked_related_agents(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    expected: &crate::AgentIdentity,
) -> Result<Vec<crate::AgentIdentity>, AuthError> {
    let model = store.model("agent")?;
    let mut query = query::filter(&model, [("hostId", json!(expected.host_id))])?;
    query.push(" FOR UPDATE");
    query
        .build()
        .fetch_all(&mut **tx)
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| rows::decode_agent(&model, row))
        .collect::<Result<Vec<_>, _>>()
        .map(|agents| {
            agents
                .into_iter()
                .filter(|agent| agent.id != expected.id)
                .collect()
        })
}

async fn locked_related_grants(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    agents: &[crate::AgentIdentity],
) -> Result<Vec<crate::AgentCapabilityGrant>, AuthError> {
    let mut grants = Vec::new();
    for agent in agents {
        grants.extend(locked_grants(store, tx, &agent.id).await?);
    }
    Ok(grants)
}

async fn locked_agent(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<crate::AgentIdentity>, AuthError> {
    let model = store.model("agent")?;
    let mut query = locked_agent_query(&model, id)?;
    query
        .build()
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_agent(&model, row))
        .transpose()
}

pub(super) fn locked_agent_query(
    model: &crate::postgres::PostgresModel<'_>,
    id: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = query::filter(model, [("id", json!(id))])?;
    query.push(" FOR UPDATE");
    Ok(query)
}

async fn locked_host(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<crate::AgentHost>, AuthError> {
    let model = store.model("agentHost")?;
    let mut query = query::filter(&model, [("id", json!(id))])?;
    query.push(" FOR UPDATE");
    query
        .build()
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_host(&model, row))
        .transpose()
}

async fn locked_grants(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Vec<crate::AgentCapabilityGrant>, AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let mut query = query::filter(&model, [("agentId", json!(id))])?;
    query.push(" FOR UPDATE");
    query
        .build()
        .fetch_all(&mut **tx)
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| rows::decode_grant(&model, row))
        .collect()
}

async fn locked_pending_approvals(
    store: &PostgresAgentAuthStore,
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Vec<crate::AgentApprovalRequest>, AuthError> {
    let model = store.model("approvalRequest")?;
    let mut query = query::filter(
        &model,
        [
            ("agentId", json!(id)),
            ("status", json!(AgentApprovalStatus::Pending.as_str())),
        ],
    )?;
    query.push(" FOR UPDATE");
    query
        .build()
        .fetch_all(&mut **tx)
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| rows::decode_approval(&model, row))
        .collect()
}

fn sort_records(
    grants: &mut [crate::AgentCapabilityGrant],
    approvals: &mut [crate::AgentApprovalRequest],
) {
    grants.sort_by(|left, right| left.id.cmp(&right.id));
    approvals.sort_by(|left, right| left.id.cmp(&right.id));
}

fn sort_related(
    agents: &mut Option<Vec<crate::AgentIdentity>>,
    grants: &mut Option<Vec<crate::AgentCapabilityGrant>>,
) {
    if let Some(values) = agents {
        values.sort_by(|left, right| left.id.cmp(&right.id));
    }
    if let Some(values) = grants {
        values.sort_by(|left, right| left.id.cmp(&right.id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_lock_is_partitioned_by_agent() {
        assert_eq!(lock_key("host-1"), "agent-capability-host:host-1");
        assert_ne!(lock_key("host-1"), lock_key("host-2"));
    }
}
