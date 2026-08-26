use super::{
    PostgresAgentAuthStore, is_unique_violation, lock_creation, query, rows, storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentCapabilityGrant, AgentStoreCreateOutcome},
};
use serde_json::{Value, json};
use sqlx::QueryBuilder;

pub(super) async fn create(
    store: &PostgresAgentAuthStore,
    grant: AgentCapabilityGrant,
) -> Result<AgentStoreCreateOutcome<AgentCapabilityGrant>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "agentCapabilityGrant").await?;
    let model = store.model("agentCapabilityGrant")?;
    let mut conflict = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    conflict.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model
        .encode("id", json!(grant.id))?
        .push_bind(&mut conflict);
    conflict.push(")");
    if conflict
        .build_query_scalar::<bool>()
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?
    {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    let mut insert = query::insert(&model, rows::grant_writes(&model, &grant)?);
    insert.push(" RETURNING ").push(model.all_projection());
    match insert.build().fetch_one(&mut *transaction).await {
        Ok(row) => {
            let grant = rows::decode_grant(&model, &row)?;
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
    find_by(
        store,
        [
            ("agentId", json!(agent_id)),
            ("capability", json!(capability)),
        ],
    )
    .await
}

pub(super) async fn find_by_id(
    store: &PostgresAgentAuthStore,
    id: &str,
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    find_by(store, [("id", json!(id))]).await
}

async fn find_by<const N: usize>(
    store: &PostgresAgentAuthStore,
    predicates: [(&'static str, Value); N],
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let mut query = query::filter(&model, predicates)?;
    query.push(" ORDER BY \"id\" LIMIT 1");
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_grant(&model, row))
        .transpose()
}

pub(super) async fn list(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
) -> Result<Vec<AgentCapabilityGrant>, AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let mut query = query::filter(&model, [("agentId", json!(agent_id))])?;
    query
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(", \"id\"");
    query
        .build()
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| rows::decode_grant(&model, row))
        .collect()
}

pub(super) async fn update(
    store: &PostgresAgentAuthStore,
    grant: AgentCapabilityGrant,
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let mut query = query::update(&model, rows::grant_writes(&model, &grant)?, &grant.id)?;
    query.push(" RETURNING ").push(model.all_projection());
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_grant(&model, row))
        .transpose()
}

pub(super) async fn delete(store: &PostgresAgentAuthStore, id: &str) -> Result<bool, AuthError> {
    let model = store.model("agentCapabilityGrant")?;
    let mut query = QueryBuilder::new("DELETE FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model.encode("id", json!(id))?.push_bind(&mut query);
    let result = query
        .build()
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
    let model = store.model("agentCapabilityGrant")?;
    let mut query = QueryBuilder::new("UPDATE ");
    query
        .push(model.quoted_table())
        .push(" SET ")
        .push(model.quoted_column("status")?)
        .push(" = ");
    model
        .encode("status", json!(crate::AgentGrantStatus::Consumed.as_str()))?
        .push_bind(&mut query);
    query
        .push(", ")
        .push(model.quoted_column("updatedAt")?)
        .push(" = ");
    model
        .encode("updatedAt", json!(now.to_rfc3339()))?
        .push_bind(&mut query);
    query.push(" WHERE \"id\" = ");
    model.encode("id", json!(id))?.push_bind(&mut query);
    let result = query
        .build()
        .execute(store.pool())
        .await
        .map_err(storage_error)?;
    Ok(result.rows_affected() > 0)
}
