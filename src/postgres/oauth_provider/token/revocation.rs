use super::super::super::{PostgresModel, rows::update_query, storage_error};
use crate::AuthError;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{QueryBuilder, types::Json};

pub(super) async fn delete_where_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    logical: &str,
    value: &str,
) -> Result<usize, AuthError> {
    let column = model.quoted_column(logical)?;
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(column)
        .push(" = ");
    model.encode(logical, json!(value))?.push_bind(&mut query);
    execute_delete(transaction, query).await
}

pub(super) async fn delete_where_text(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    logical: &str,
    value: &str,
) -> Result<usize, AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(logical)?)
        .push(" = ")
        .push_bind(value.to_owned());
    execute_delete(transaction, query).await
}

pub(super) async fn delete_where_ids(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    logical: &str,
    values: &[String],
) -> Result<usize, AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query.push(model.quoted_table()).push(" WHERE ");
    push_typed_values_predicate(&mut query, model, logical, values)?;
    execute_delete(transaction, query).await
}

pub(super) fn push_typed_values_predicate(
    query: &mut QueryBuilder<'static, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    logical: &str,
    values: &[String],
) -> Result<(), AuthError> {
    if values.is_empty() {
        query.push("FALSE");
        return Ok(());
    }
    query.push("(");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            query.push(" OR ");
        }
        query.push(model.quoted_column(logical)?).push(" = ");
        model.encode(logical, json!(value))?.push_bind(query);
    }
    query.push(")");
    Ok(())
}

async fn execute_delete(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mut query: QueryBuilder<'static, sqlx::Postgres>,
) -> Result<usize, AuthError> {
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|result| result.rows_affected() as usize)
        .map_err(storage_error)
}

pub(super) async fn revoke_for_session(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    session_id: &str,
    revoked_at: DateTime<Utc>,
    preserve_offline_access: bool,
) -> Result<usize, AuthError> {
    if preserve_offline_access {
        return revoke_online_refresh_tokens(transaction, model, session_id, revoked_at).await;
    }
    let writes = model.encode_fields([("revoked", Value::String(revoked_at.to_rfc3339()))])?;
    let mut query = update_query(model, writes);
    query
        .push(" WHERE ")
        .push(model.quoted_column("sessionId")?)
        .push(" = ");
    model
        .encode("sessionId", json!(session_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("revoked")?)
        .push(" IS NULL");
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|result| result.rows_affected() as usize)
        .map_err(storage_error)
}

async fn revoke_online_refresh_tokens(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    session_id: &str,
    revoked_at: DateTime<Utc>,
) -> Result<usize, AuthError> {
    let mut select = QueryBuilder::new("SELECT \"id\"::TEXT, ");
    select
        .push(model.quoted_column("scopes")?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("sessionId")?)
        .push(" = ");
    model
        .encode("sessionId", json!(session_id))?
        .push_bind(&mut select);
    select
        .push(" AND ")
        .push(model.quoted_column("revoked")?)
        .push(" IS NULL FOR UPDATE");
    let ids = select
        .build_query_as::<(String, Json<Vec<String>>)>()
        .fetch_all(&mut **transaction)
        .await
        .map_err(storage_error)?
        .into_iter()
        .filter_map(|(id, scopes)| {
            (!scopes.0.iter().any(|scope| scope == "offline_access")).then_some(id)
        })
        .collect::<Vec<_>>();
    let writes = model.encode_fields([("revoked", Value::String(revoked_at.to_rfc3339()))])?;
    let mut update = update_query(model, writes);
    update.push(" WHERE ");
    push_typed_values_predicate(&mut update, model, "id", &ids)?;
    update
        .build()
        .execute(&mut **transaction)
        .await
        .map(|result| result.rows_affected() as usize)
        .map_err(storage_error)
}
