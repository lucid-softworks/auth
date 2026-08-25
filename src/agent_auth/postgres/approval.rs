use super::{
    PostgresAgentAuthStore, is_unique_violation, lock_creation, query,
    rows::{APPROVAL_FIELDS, ApprovalRow},
    storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentApprovalRequest, AgentStoreCreateOutcome, schema::AgentAuthModel},
};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresAgentAuthStore,
    approval: AgentApprovalRequest,
) -> Result<AgentStoreCreateOutcome<AgentApprovalRequest>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "approvalRequest").await?;
    let model = store.schema.model(AgentAuthModel::ApprovalRequest);
    let conflict = sqlx::query_scalar::<_, bool>(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE \"id\"=$1 OR ($2::TEXT IS NOT NULL AND {}=$2))",
        model.table(),
        model.column("userCodeHash"),
    ))
    .bind(&approval.id)
    .bind(&approval.user_code_hash)
    .fetch_one(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if conflict {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    let result = sqlx::query_as::<_, ApprovalRow>(&query::insert(
        &store.schema,
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
    .fetch_one(&mut *transaction)
    .await;
    match result {
        Ok(row) => {
            let approval = row.try_into()?;
            transaction.commit().await.map_err(storage_error)?;
            Ok(AgentStoreCreateOutcome::Created(approval))
        }
        Err(error) if is_unique_violation(&error) => Ok(AgentStoreCreateOutcome::UniqueConflict),
        Err(error) => Err(storage_error(error)),
    }
}

pub(super) async fn find(
    store: &PostgresAgentAuthStore,
    field: &str,
    value: &str,
) -> Result<Option<AgentApprovalRequest>, AuthError> {
    convert(
        sqlx::query_as::<_, ApprovalRow>(&query::select(
            &store.schema,
            AgentAuthModel::ApprovalRequest,
            APPROVAL_FIELDS,
            &[field],
            " LIMIT 1",
        ))
        .bind(value)
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

pub(super) async fn list_pending_for_user(
    store: &PostgresAgentAuthStore,
    user_id: Uuid,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    let model = store.schema.model(AgentAuthModel::ApprovalRequest);
    let order = format!(" ORDER BY {}, \"id\"", model.column("createdAt"));
    sqlx::query_as::<_, ApprovalRow>(&query::select(
        &store.schema,
        AgentAuthModel::ApprovalRequest,
        APPROVAL_FIELDS,
        &["userId", "status"],
        &order,
    ))
    .bind(user_id)
    .bind("pending")
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?
    .into_iter()
    .map(TryInto::try_into)
    .collect()
}

pub(super) async fn list_pending_for_agent(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    let model = store.schema.model(AgentAuthModel::ApprovalRequest);
    let order = format!(" ORDER BY {}, \"id\"", model.column("createdAt"));
    sqlx::query_as::<_, ApprovalRow>(&query::select(
        &store.schema,
        AgentAuthModel::ApprovalRequest,
        APPROVAL_FIELDS,
        &["agentId", "status"],
        &order,
    ))
    .bind(agent_id)
    .bind("pending")
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?
    .into_iter()
    .map(TryInto::try_into)
    .collect()
}

pub(super) async fn list_for_agent(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    sqlx::query_as::<_, ApprovalRow>(&query::select(
        &store.schema,
        AgentAuthModel::ApprovalRequest,
        APPROVAL_FIELDS,
        &["agentId"],
        " ORDER BY \"id\"",
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
    approval: AgentApprovalRequest,
) -> Result<Option<AgentApprovalRequest>, AuthError> {
    convert(
        sqlx::query_as::<_, ApprovalRow>(&query::update(
            &store.schema,
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
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?,
    )
}

fn convert(row: Option<ApprovalRow>) -> Result<Option<AgentApprovalRequest>, AuthError> {
    row.map(TryInto::try_into).transpose()
}
