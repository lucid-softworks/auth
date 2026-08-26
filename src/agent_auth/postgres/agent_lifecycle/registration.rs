use crate::{
    AuthError,
    agent_auth::{AgentRegistrationBundle, AgentRegistrationOutcome},
};
use sqlx::{Postgres, Transaction};
use std::collections::HashSet;

use super::{
    super::{PostgresAgentAuthStore, lock_creation, storage_error},
    inserts,
};

pub(in crate::agent_auth::postgres) async fn register(
    store: &PostgresAgentAuthStore,
    bundle: AgentRegistrationBundle,
) -> Result<AgentRegistrationOutcome, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_models(&mut transaction).await?;
    if conflicts(store, &mut transaction, &bundle).await? {
        return Ok(AgentRegistrationOutcome::UniqueConflict);
    }
    persist(store, &mut transaction, &bundle).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(AgentRegistrationOutcome::Registered(Box::new(bundle)))
}

async fn lock_models(transaction: &mut Transaction<'_, Postgres>) -> Result<(), AuthError> {
    for model in [
        "agentHost",
        "agent",
        "agentCapabilityGrant",
        "approvalRequest",
    ] {
        lock_creation(transaction, model).await?;
    }
    Ok(())
}

async fn conflicts(
    store: &PostgresAgentAuthStore,
    transaction: &mut Transaction<'_, Postgres>,
    bundle: &AgentRegistrationBundle,
) -> Result<bool, AuthError> {
    if duplicate_bundle_values(bundle) {
        return Ok(true);
    }
    Ok(host_conflict(store, transaction, bundle).await?
        || agent_conflict(store, transaction, bundle).await?
        || grant_conflict(store, transaction, bundle).await?
        || approval_conflict(store, transaction, bundle).await?)
}

fn duplicate_bundle_values(bundle: &AgentRegistrationBundle) -> bool {
    if bundle
        .host
        .as_ref()
        .is_some_and(|host| host.id != bundle.agent.host_id)
    {
        return true;
    }
    let mut grant_ids = HashSet::new();
    let mut grant_pairs = HashSet::new();
    bundle.grants.iter().any(|grant| {
        !grant_ids.insert(&grant.id)
            || !grant_pairs.insert((&grant.agent_id, &grant.capability))
            || grant.agent_id != bundle.agent.id
    })
}

async fn host_conflict(
    store: &PostgresAgentAuthStore,
    transaction: &mut Transaction<'_, Postgres>,
    bundle: &AgentRegistrationBundle,
) -> Result<bool, AuthError> {
    let Some(host) = &bundle.host else {
        return Ok(false);
    };
    let model = store.model("agentHost")?;
    sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {}=$1 OR ($2::TEXT IS NOT NULL AND {}=$2) OR ($3::TEXT IS NOT NULL AND {}=$3))",
        model.quoted_table(),
        model.quoted_column("id")?,
        model.quoted_column("kid")?,
        model.quoted_column("publicKey")?,
    ))
    .bind(&host.id)
    .bind(&host.kid)
    .bind(&host.public_key)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)
}

async fn agent_conflict(
    store: &PostgresAgentAuthStore,
    transaction: &mut Transaction<'_, Postgres>,
    bundle: &AgentRegistrationBundle,
) -> Result<bool, AuthError> {
    let model = store.model("agent")?;
    sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {}=$1 OR ($2::TEXT IS NOT NULL AND {}=$2) OR {}=$3)",
        model.quoted_table(),
        model.quoted_column("id")?,
        model.quoted_column("kid")?,
        model.quoted_column("publicKey")?,
    ))
    .bind(&bundle.agent.id)
    .bind(&bundle.agent.kid)
    .bind(&bundle.agent.public_key)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)
}

async fn grant_conflict(
    store: &PostgresAgentAuthStore,
    transaction: &mut Transaction<'_, Postgres>,
    bundle: &AgentRegistrationBundle,
) -> Result<bool, AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {}=$1 OR ({}=$2 AND {}=$3))",
        model.quoted_table(),
        model.quoted_column("id")?,
        model.quoted_column("agentId")?,
        model.quoted_column("capability")?,
    );
    for grant in &bundle.grants {
        let conflict = sqlx::query_scalar(&sql)
            .bind(&grant.id)
            .bind(&grant.agent_id)
            .bind(&grant.capability)
            .fetch_one(&mut **transaction)
            .await
            .map_err(storage_error)?;
        if conflict {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn approval_conflict(
    store: &PostgresAgentAuthStore,
    transaction: &mut Transaction<'_, Postgres>,
    bundle: &AgentRegistrationBundle,
) -> Result<bool, AuthError> {
    let Some(approval) = &bundle.approval else {
        return Ok(false);
    };
    let model = store.model("approvalRequest")?;
    sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {}=$1 OR ($2::TEXT IS NOT NULL AND {}=$2))",
        model.quoted_table(),
        model.quoted_column("id")?,
        model.quoted_column("userCodeHash")?,
    ))
    .bind(&approval.id)
    .bind(&approval.user_code_hash)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage_error)
}

async fn persist(
    store: &PostgresAgentAuthStore,
    transaction: &mut Transaction<'_, Postgres>,
    bundle: &AgentRegistrationBundle,
) -> Result<(), AuthError> {
    if let Some(host) = &bundle.host {
        inserts::host(transaction, store, host).await?;
    }
    inserts::agent(transaction, store, &bundle.agent).await?;
    for grant in &bundle.grants {
        inserts::grant(transaction, store, grant).await?;
    }
    if let Some(approval) = &bundle.approval {
        inserts::approval(transaction, store, approval).await?;
    }
    Ok(())
}
