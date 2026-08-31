use super::{delete_many, find_one};
use crate::{AuthError, mysql::{MySqlFilter, query::predicate, schema::MySqlSchema}};
use serde_json::{Map, Value};
use sqlx::{Connection, MySql, MySqlConnection, QueryBuilder, Transaction};

pub(in crate::mysql) async fn consume_one(connection: &mut MySqlConnection, schema: &MySqlSchema, model: &str, filters: &[MySqlFilter]) -> Result<Option<Map<String, Value>>, AuthError> {
    let mut transaction = connection.begin().await.map_err(storage)?;
    let result = consume_one_in_transaction(&mut transaction, schema, model, filters).await;
    finish(transaction, result).await
}

pub(in crate::mysql) async fn consume_one_in_transaction(transaction: &mut Transaction<'_, MySql>, schema: &MySqlSchema, model_name: &str, filters: &[MySqlFilter]) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut select = QueryBuilder::<MySql>::new("select ");
    select.push(model.all_projection()).push(" from ").push(model.quoted_table());
    predicate::push(&mut select, &model, filters)?;
    select.push(" limit 1 for update");
    let Some(row) = select.build().fetch_optional(&mut **transaction).await.map_err(storage)? else { return Ok(None); };
    let record = model.decode_all(&row)?;
    delete_locked(transaction, schema, model_name, record).await
}

pub(in crate::mysql) async fn consume_latest(connection: &mut MySqlConnection, schema: &MySqlSchema, model_name: &str, filters: &[MySqlFilter], sort_field: &str) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut select = QueryBuilder::<MySql>::new("select ");
    select.push(model.all_projection()).push(" from ").push(model.quoted_table());
    predicate::push(&mut select, &model, filters)?;
    select.push(" order by ").push(model.quoted_column(sort_field)?).push(" desc, `id` desc limit 1 for update");
    let Some(row) = select.build().fetch_optional(&mut *connection).await.map_err(storage)? else { return Ok(None); };
    let record = model.decode_all(&row)?;
    delete_locked(connection, schema, model_name, record).await
}

async fn delete_locked(connection: &mut MySqlConnection, schema: &MySqlSchema, model: &str, record: Map<String, Value>) -> Result<Option<Map<String, Value>>, AuthError> {
    let id = record.get("id").cloned().ok_or_else(|| AuthError::Storage("locked MySQL row has no id".into()))?;
    let deleted = delete_many(connection, schema, model, &[MySqlFilter::equal("id", id)]).await?;
    Ok((deleted > 0).then_some(record))
}

pub(in crate::mysql) async fn increment_one(connection: &mut MySqlConnection, schema: &MySqlSchema, model: &str, filters: &[MySqlFilter], increments: Map<String, Value>, set: Map<String, Value>) -> Result<Option<Map<String, Value>>, AuthError> {
    let mut transaction = connection.begin().await.map_err(storage)?;
    let result = increment_one_in_transaction(&mut transaction, schema, model, filters, increments, set).await;
    finish(transaction, result).await
}

pub(in crate::mysql) async fn increment_one_in_transaction(transaction: &mut Transaction<'_, MySql>, schema: &MySqlSchema, model_name: &str, filters: &[MySqlFilter], increments: Map<String, Value>, mut set: Map<String, Value>) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut select = QueryBuilder::<MySql>::new("select `id` as `id` from ");
    select.push(model.quoted_table());
    predicate::push(&mut select, &model, filters)?;
    select.push(" limit 1 for update");
    let Some(row) = select.build().fetch_optional(&mut **transaction).await.map_err(storage)? else { return Ok(None); };
    let id = crate::mysql::value::decode_id(&row, "id", model.id_type())?;
    for field in increments.keys() { set.remove(field); }
    let mut update = QueryBuilder::<MySql>::new("update ");
    update.push(model.quoted_table()).push(" set ");
    let assignments = push_assignments(&mut update, &model, set, increments)?;
    if assignments == 0 { return find_by_id(transaction, schema, model_name, id).await; }
    let mut exact_filters = filters.to_vec();
    exact_filters.push(MySqlFilter::equal("id", id.clone()));
    predicate::push(&mut update, &model, &exact_filters)?;
    if update.build().execute(&mut **transaction).await.map_err(storage)?.rows_affected() == 0 { return Ok(None); }
    find_by_id(transaction, schema, model_name, id).await
}

fn push_assignments(query: &mut QueryBuilder<'_, MySql>, model: &crate::mysql::schema::MySqlModel<'_>, set: Map<String, Value>, increments: Map<String, Value>) -> Result<usize, AuthError> {
    let mut count = 0;
    for (field, value) in set { separator(query, &mut count); query.push(model.quoted_column(&field)?).push(" = "); model.encode(&field, value)?.push_bind(query); }
    for (field, delta) in increments { separator(query, &mut count); let column = model.quoted_column(&field)?; query.push(column).push(" = ").push(column).push(" + "); model.encode(&field, delta)?.push_bind(query); }
    Ok(count)
}

fn separator(query: &mut QueryBuilder<'_, MySql>, count: &mut usize) { if *count > 0 { query.push(", "); } *count += 1; }

async fn find_by_id(connection: &mut MySqlConnection, schema: &MySqlSchema, model: &str, id: Value) -> Result<Option<Map<String, Value>>, AuthError> { find_one(connection, schema, model, &[MySqlFilter::equal("id", id)], &[]).await }

async fn finish<T>(transaction: Transaction<'_, MySql>, result: Result<T, AuthError>) -> Result<T, AuthError> {
    match result {
        Ok(value) => { transaction.commit().await.map_err(storage)?; Ok(value) }
        Err(error) => { if let Err(rollback) = transaction.rollback().await { tracing::warn!(error = %rollback, "failed to roll back MySQL adapter transaction"); } Err(error) }
    }
}

fn storage(error: sqlx::Error) -> AuthError { AuthError::Storage(error.to_string()) }
