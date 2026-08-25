use super::{
    PostgresAgentAuthStore, is_unique_violation, lock_creation, query,
    rows::{AGENT_FIELDS, AgentRow, encode_optional_json},
    storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentIdentity, AgentStoreCreateOutcome, schema::AgentAuthModel},
};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresAgentAuthStore,
    agent: AgentIdentity,
) -> Result<AgentStoreCreateOutcome<AgentIdentity>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "agent").await?;
    let model = store.schema.model(AgentAuthModel::Agent);
    let conflict = sqlx::query_scalar::<_, bool>(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE \"id\"=$1 OR ($2::TEXT IS NOT NULL AND {}=$2) OR {}=$3)",
        model.table(),
        model.column("kid"),
        model.column("publicKey"),
    ))
    .bind(&agent.id)
    .bind(&agent.kid)
    .bind(&agent.public_key)
    .fetch_one(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if conflict {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    let metadata = encode_optional_json(&agent.metadata)?;
    let result = sqlx::query_as::<_, AgentRow>(&query::insert(
        &store.schema,
        AgentAuthModel::Agent,
        AGENT_FIELDS,
    ))
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
    .fetch_one(&mut *transaction)
    .await;
    match result {
        Ok(row) => {
            let agent = row.try_into()?;
            transaction.commit().await.map_err(storage_error)?;
            Ok(AgentStoreCreateOutcome::Created(agent))
        }
        Err(error) if is_unique_violation(&error) => Ok(AgentStoreCreateOutcome::UniqueConflict),
        Err(error) => Err(storage_error(error)),
    }
}

pub(super) async fn find(
    store: &PostgresAgentAuthStore,
    field: &str,
    value: &str,
) -> Result<Option<AgentIdentity>, AuthError> {
    convert(
        sqlx::query_as::<_, AgentRow>(&query::select(
            &store.schema,
            AgentAuthModel::Agent,
            AGENT_FIELDS,
            &[field],
            " LIMIT 1",
        ))
        .bind(value)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn list_for_user(
    store: &PostgresAgentAuthStore,
    user_id: Uuid,
) -> Result<Vec<AgentIdentity>, AuthError> {
    let model = store.schema.model(AgentAuthModel::Agent);
    let order = format!(" ORDER BY {}, \"id\"", model.column("createdAt"));
    convert_many(
        sqlx::query_as::<_, AgentRow>(&query::select(
            &store.schema,
            AgentAuthModel::Agent,
            AGENT_FIELDS,
            &["userId"],
            &order,
        ))
        .bind(user_id)
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn list_for_host(
    store: &PostgresAgentAuthStore,
    host_id: &str,
) -> Result<Vec<AgentIdentity>, AuthError> {
    let model = store.schema.model(AgentAuthModel::Agent);
    let order = format!(" ORDER BY {}, \"id\"", model.column("createdAt"));
    convert_many(
        sqlx::query_as::<_, AgentRow>(&query::select(
            &store.schema,
            AgentAuthModel::Agent,
            AGENT_FIELDS,
            &["hostId"],
            &order,
        ))
        .bind(host_id)
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn update(
    store: &PostgresAgentAuthStore,
    agent: AgentIdentity,
) -> Result<Option<AgentIdentity>, AuthError> {
    let metadata = encode_optional_json(&agent.metadata)?;
    convert(
        sqlx::query_as::<_, AgentRow>(&query::update(
            &store.schema,
            AgentAuthModel::Agent,
            AGENT_FIELDS,
        ))
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
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

fn convert(row: Option<AgentRow>) -> Result<Option<AgentIdentity>, AuthError> {
    row.map(TryInto::try_into).transpose()
}

fn convert_many(rows: Vec<AgentRow>) -> Result<Vec<AgentIdentity>, AuthError> {
    rows.into_iter().map(TryInto::try_into).collect()
}
