use super::{
    PostgresAgentAuthStore, is_unique_violation, lock_creation, query, rows, storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentIdentity, AgentStoreCreateOutcome},
};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};

pub(super) async fn create(
    store: &PostgresAgentAuthStore,
    agent: AgentIdentity,
) -> Result<AgentStoreCreateOutcome<AgentIdentity>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "agent").await?;
    let model = store.model("agent")?;
    if conflicts(&model, &agent, &mut transaction).await? {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    let mut insert = query::insert(&model, rows::agent_writes(&model, &agent)?);
    insert.push(" RETURNING ").push(model.all_projection());
    let result = insert.build().fetch_one(&mut *transaction).await;
    match result {
        Ok(row) => {
            let agent = rows::decode_agent(&model, &row)?;
            transaction.commit().await.map_err(storage_error)?;
            Ok(AgentStoreCreateOutcome::Created(agent))
        }
        Err(error) if is_unique_violation(&error) => Ok(AgentStoreCreateOutcome::UniqueConflict),
        Err(error) => Err(storage_error(error)),
    }
}

async fn conflicts(
    model: &crate::postgres::PostgresModel<'_>,
    agent: &AgentIdentity,
    transaction: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model.encode("id", json!(agent.id))?.push_bind(&mut query);
    query.push(" OR (");
    model
        .encode("kid", optional_string(agent.kid.clone()))?
        .push_bind(&mut query);
    query
        .push(" IS NOT NULL AND ")
        .push(model.quoted_column("kid")?)
        .push(" = ");
    model
        .encode("kid", optional_string(agent.kid.clone()))?
        .push_bind(&mut query);
    query
        .push(") OR ")
        .push(model.quoted_column("publicKey")?)
        .push(" = ");
    model
        .encode("publicKey", json!(agent.public_key))?
        .push_bind(&mut query);
    query.push(")");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn find(
    store: &PostgresAgentAuthStore,
    field: &'static str,
    value: &str,
) -> Result<Option<AgentIdentity>, AuthError> {
    let model = store.model("agent")?;
    let mut query = query::filter(&model, [(field, Value::String(value.to_owned()))])?;
    query.push(" ORDER BY \"id\" LIMIT 1");
    fetch_optional(store, &model, query).await
}

pub(super) async fn list_for_user(
    store: &PostgresAgentAuthStore,
    user_id: &str,
) -> Result<Vec<AgentIdentity>, AuthError> {
    list_by(store, "userId", json!(user_id)).await
}

pub(super) async fn list_for_host(
    store: &PostgresAgentAuthStore,
    host_id: &str,
) -> Result<Vec<AgentIdentity>, AuthError> {
    list_by(store, "hostId", json!(host_id)).await
}

async fn list_by(
    store: &PostgresAgentAuthStore,
    field: &'static str,
    value: Value,
) -> Result<Vec<AgentIdentity>, AuthError> {
    let model = store.model("agent")?;
    let mut query = query::filter(&model, [(field, value)])?;
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
        .map(|row| rows::decode_agent(&model, row))
        .collect()
}

pub(super) async fn update(
    store: &PostgresAgentAuthStore,
    agent: AgentIdentity,
) -> Result<Option<AgentIdentity>, AuthError> {
    let model = store.model("agent")?;
    let mut query = query::update(&model, rows::agent_writes(&model, &agent)?, &agent.id)?;
    query.push(" RETURNING ").push(model.all_projection());
    fetch_optional(store, &model, query).await
}

async fn fetch_optional(
    store: &PostgresAgentAuthStore,
    model: &crate::postgres::PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
) -> Result<Option<AgentIdentity>, AuthError> {
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_agent(model, row))
        .transpose()
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}
