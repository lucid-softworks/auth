use super::{
    PostgresAgentAuthStore, is_unique_violation, lock_creation, query,
    rows::{HOST_FIELDS, HostRow, encode_json},
    storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentHost, AgentStoreCreateOutcome, schema::AgentAuthModel},
};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresAgentAuthStore,
    host: AgentHost,
) -> Result<AgentStoreCreateOutcome<AgentHost>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "agentHost").await?;
    let model = store.schema.model(AgentAuthModel::AgentHost);
    let conflict = sqlx::query_scalar::<_, bool>(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE \"id\"=$1 OR ($2::TEXT IS NOT NULL AND {}=$2) OR ($3::TEXT IS NOT NULL AND {}=$3))",
        model.table(),
        model.column("kid"),
        model.column("enrollmentTokenHash"),
    ))
    .bind(&host.id)
    .bind(&host.kid)
    .bind(&host.enrollment_token_hash)
    .fetch_one(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if conflict {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    let capabilities = encode_json(&host.default_capabilities)?;
    let result = sqlx::query_as::<_, HostRow>(&query::insert(
        &store.schema,
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
    .fetch_one(&mut *transaction)
    .await;
    match result {
        Ok(row) => {
            let host = row.try_into()?;
            transaction.commit().await.map_err(storage_error)?;
            Ok(AgentStoreCreateOutcome::Created(host))
        }
        Err(error) if is_unique_violation(&error) => Ok(AgentStoreCreateOutcome::UniqueConflict),
        Err(error) => Err(storage_error(error)),
    }
}

pub(super) async fn find(
    store: &PostgresAgentAuthStore,
    field: &str,
    value: &str,
) -> Result<Option<AgentHost>, AuthError> {
    convert(
        sqlx::query_as::<_, HostRow>(&query::select(
            &store.schema,
            AgentAuthModel::AgentHost,
            HOST_FIELDS,
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
) -> Result<Vec<AgentHost>, AuthError> {
    let model = store.schema.model(AgentAuthModel::AgentHost);
    let order = format!(" ORDER BY {}, \"id\"", model.column("createdAt"));
    sqlx::query_as::<_, HostRow>(&query::select(
        &store.schema,
        AgentAuthModel::AgentHost,
        HOST_FIELDS,
        &["userId"],
        &order,
    ))
    .bind(user_id)
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?
    .into_iter()
    .map(TryInto::try_into)
    .collect()
}

pub(super) async fn update(
    store: &PostgresAgentAuthStore,
    host: AgentHost,
) -> Result<Option<AgentHost>, AuthError> {
    let capabilities = encode_json(&host.default_capabilities)?;
    convert(
        sqlx::query_as::<_, HostRow>(&query::update(
            &store.schema,
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
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

fn convert(row: Option<HostRow>) -> Result<Option<AgentHost>, AuthError> {
    row.map(TryInto::try_into).transpose()
}
