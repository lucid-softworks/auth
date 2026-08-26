use super::{
    PostgresAgentAuthStore, is_unique_violation, lock_creation, query,
    rows::{self},
    storage_error,
};
use crate::{
    AuthError,
    agent_auth::{AgentHost, AgentStoreCreateOutcome},
};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};

pub(super) async fn create(
    store: &PostgresAgentAuthStore,
    host: AgentHost,
) -> Result<AgentStoreCreateOutcome<AgentHost>, AuthError> {
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    lock_creation(&mut transaction, "agentHost").await?;
    let model = store.model("agentHost")?;
    if conflicts(&model, &host, &mut transaction).await? {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    let mut insert = query::insert(&model, rows::host_writes(&model, &host)?);
    insert.push(" RETURNING ").push(model.all_projection());
    let result = insert.build().fetch_one(&mut *transaction).await;
    match result {
        Ok(row) => {
            let host = rows::decode_host(&model, &row)?;
            transaction.commit().await.map_err(storage_error)?;
            Ok(AgentStoreCreateOutcome::Created(host))
        }
        Err(error) if is_unique_violation(&error) => Ok(AgentStoreCreateOutcome::UniqueConflict),
        Err(error) => Err(storage_error(error)),
    }
}

async fn conflicts(
    model: &crate::postgres::PostgresModel<'_>,
    host: &AgentHost,
    transaction: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model.encode("id", json!(host.id))?.push_bind(&mut query);
    for (field, value) in [
        ("kid", host.kid.clone()),
        ("enrollmentTokenHash", host.enrollment_token_hash.clone()),
    ] {
        query.push(" OR (");
        model
            .encode(field, optional_string(value.clone()))?
            .push_bind(&mut query);
        query
            .push(" IS NOT NULL AND ")
            .push(model.quoted_column(field)?)
            .push(" = ");
        model
            .encode(field, optional_string(value))?
            .push_bind(&mut query);
        query.push(")");
    }
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
) -> Result<Option<AgentHost>, AuthError> {
    let model = store.model("agentHost")?;
    let mut query = query::filter(&model, [(field, Value::String(value.to_owned()))])?;
    query.push(" ORDER BY \"id\" LIMIT 1");
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_host(&model, row))
        .transpose()
}

pub(super) async fn list_for_user(
    store: &PostgresAgentAuthStore,
    user_id: &str,
) -> Result<Vec<AgentHost>, AuthError> {
    let model = store.model("agentHost")?;
    let mut query = query::filter(&model, [("userId", json!(user_id))])?;
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
        .map(|row| rows::decode_host(&model, row))
        .collect()
}

pub(super) async fn update(
    store: &PostgresAgentAuthStore,
    host: AgentHost,
) -> Result<Option<AgentHost>, AuthError> {
    let model = store.model("agentHost")?;
    let mut query = query::update(&model, rows::host_writes(&model, &host)?, &host.id)?;
    query.push(" RETURNING ").push(model.all_projection());
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_host(&model, row))
        .transpose()
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}
