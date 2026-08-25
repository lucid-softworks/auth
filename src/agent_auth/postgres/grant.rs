use super::{
    PostgresAgentAuthStore, is_unique_violation, lock_creation, query,
    rows::{GRANT_FIELDS, GrantRow, encode_optional_json},
    storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentCapabilityGrant, AgentStoreCreateOutcome, schema::AgentAuthModel},
};

pub(super) async fn create(
    store: &PostgresAgentAuthStore,
    grant: AgentCapabilityGrant,
) -> Result<AgentStoreCreateOutcome<AgentCapabilityGrant>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "agentCapabilityGrant").await?;
    let model = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
    let conflict = sqlx::query_scalar::<_, bool>(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE \"id\"=$1)",
        model.table(),
    ))
    .bind(&grant.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if conflict {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    let constraints = encode_optional_json(&grant.constraints)?;
    let result = sqlx::query_as::<_, GrantRow>(&query::insert(
        &store.schema,
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
    .fetch_one(&mut *transaction)
    .await;
    match result {
        Ok(row) => {
            let grant = row.try_into()?;
            transaction.commit().await.map_err(storage_error)?;
            Ok(AgentStoreCreateOutcome::Created(grant))
        }
        Err(error) if is_unique_violation(&error) => Ok(AgentStoreCreateOutcome::UniqueConflict),
        Err(error) => Err(storage_error(error)),
    }
}

pub(super) async fn find(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
    capability: &str,
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    convert(
        sqlx::query_as::<_, GrantRow>(&query::select(
            &store.schema,
            AgentAuthModel::AgentCapabilityGrant,
            GRANT_FIELDS,
            &["agentId", "capability"],
            " LIMIT 1",
        ))
        .bind(agent_id)
        .bind(capability)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn find_by_id(
    store: &PostgresAgentAuthStore,
    id: &str,
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    convert(
        sqlx::query_as::<_, GrantRow>(&query::select(
            &store.schema,
            AgentAuthModel::AgentCapabilityGrant,
            GRANT_FIELDS,
            &["id"],
            " LIMIT 1",
        ))
        .bind(id)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn list(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
) -> Result<Vec<AgentCapabilityGrant>, AuthError> {
    let model = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
    let order = format!(" ORDER BY {}, \"id\"", model.column("createdAt"));
    sqlx::query_as::<_, GrantRow>(&query::select(
        &store.schema,
        AgentAuthModel::AgentCapabilityGrant,
        GRANT_FIELDS,
        &["agentId"],
        &order,
    ))
    .bind(agent_id)
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?
    .into_iter()
    .map(TryInto::try_into)
    .collect()
}

pub(super) async fn update(
    store: &PostgresAgentAuthStore,
    grant: AgentCapabilityGrant,
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    let constraints = encode_optional_json(&grant.constraints)?;
    convert(
        sqlx::query_as::<_, GrantRow>(&query::update(
            &store.schema,
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
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn delete(store: &PostgresAgentAuthStore, id: &str) -> Result<bool, AuthError> {
    let model = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
    let result = sqlx::query(&format!("DELETE FROM {} WHERE \"id\"=$1", model.table()))
        .bind(id)
        .execute(store.pool())
        .await
        .map_err(storage_error)?;
    Ok(result.rows_affected() > 0)
}

pub(super) async fn consume(
    store: &PostgresAgentAuthStore,
    id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, AuthError> {
    let model = store.schema.model(AgentAuthModel::AgentCapabilityGrant);
    let result = sqlx::query(&format!(
        "UPDATE {} SET {}=$2, {}=$3 WHERE \"id\"=$1",
        model.table(),
        model.column("status"),
        model.column("updatedAt")
    ))
    .bind(id)
    .bind(crate::AgentGrantStatus::Consumed.as_str())
    .bind(now)
    .execute(store.pool())
    .await
    .map_err(storage_error)?;
    Ok(result.rows_affected() > 0)
}

fn convert(row: Option<GrantRow>) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    row.map(TryInto::try_into).transpose()
}
