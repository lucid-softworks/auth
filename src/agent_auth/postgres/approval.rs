use super::{
    PostgresAgentAuthStore, is_unique_violation, lock_creation, query, rows, storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentApprovalRequest, AgentStoreCreateOutcome},
};
use serde_json::{Value, json};
use sqlx::QueryBuilder;

pub(super) async fn create(
    store: &PostgresAgentAuthStore,
    approval: AgentApprovalRequest,
) -> Result<AgentStoreCreateOutcome<AgentApprovalRequest>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "approvalRequest").await?;
    let model = store.model("approvalRequest")?;
    let mut conflict = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    conflict.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model
        .encode("id", json!(approval.id))?
        .push_bind(&mut conflict);
    conflict.push(" OR (");
    model
        .encode(
            "userCodeHash",
            optional_string(approval.user_code_hash.clone()),
        )?
        .push_bind(&mut conflict);
    conflict
        .push(" IS NOT NULL AND ")
        .push(model.quoted_column("userCodeHash")?)
        .push(" = ");
    model
        .encode(
            "userCodeHash",
            optional_string(approval.user_code_hash.clone()),
        )?
        .push_bind(&mut conflict);
    conflict.push("))");
    if conflict
        .build_query_scalar::<bool>()
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?
    {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    let mut insert = query::insert(&model, rows::approval_writes(&model, &approval)?);
    insert.push(" RETURNING ").push(model.all_projection());
    match insert.build().fetch_one(&mut *transaction).await {
        Ok(row) => {
            let approval = rows::decode_approval(&model, &row)?;
            transaction.commit().await.map_err(storage_error)?;
            Ok(AgentStoreCreateOutcome::Created(approval))
        }
        Err(error) if is_unique_violation(&error) => Ok(AgentStoreCreateOutcome::UniqueConflict),
        Err(error) => Err(storage_error(error)),
    }
}

pub(super) async fn find(
    store: &PostgresAgentAuthStore,
    field: &'static str,
    value: &str,
) -> Result<Option<AgentApprovalRequest>, AuthError> {
    let model = store.model("approvalRequest")?;
    let mut query = query::filter(&model, [(field, Value::String(value.to_owned()))])?;
    query.push(" ORDER BY \"id\" LIMIT 1");
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_approval(&model, row))
        .transpose()
}

pub(super) async fn list_pending_for_user(
    store: &PostgresAgentAuthStore,
    user_id: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    list_by(
        store,
        [("userId", json!(user_id)), ("status", json!("pending"))],
        true,
    )
    .await
}

pub(super) async fn list_pending_for_agent(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    list_by(
        store,
        [("agentId", json!(agent_id)), ("status", json!("pending"))],
        true,
    )
    .await
}

pub(super) async fn list_for_agent(
    store: &PostgresAgentAuthStore,
    agent_id: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    list_by(store, [("agentId", json!(agent_id))], false).await
}

async fn list_by<const N: usize>(
    store: &PostgresAgentAuthStore,
    predicates: [(&'static str, Value); N],
    chronological: bool,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    let model = store.model("approvalRequest")?;
    let mut query = query::filter(&model, predicates)?;
    query.push(" ORDER BY ");
    if chronological {
        query.push(model.quoted_column("createdAt")?).push(", ");
    }
    query.push("\"id\"");
    query
        .build()
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| rows::decode_approval(&model, row))
        .collect()
}

pub(super) async fn update(
    store: &PostgresAgentAuthStore,
    approval: AgentApprovalRequest,
) -> Result<Option<AgentApprovalRequest>, AuthError> {
    let model = store.model("approvalRequest")?;
    let mut query = query::update(
        &model,
        rows::approval_writes(&model, &approval)?,
        &approval.id,
    )?;
    query.push(" RETURNING ").push(model.all_projection());
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_approval(&model, row))
        .transpose()
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}
