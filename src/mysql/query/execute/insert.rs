use super::{find_many, find_one};
use crate::{AuthError, DatabaseIdType, mysql::{MySqlFilter, MySqlFindOptions, schema::MySqlSchema}};
use serde_json::{Map, Value};
use sqlx::{MySql, MySqlConnection, QueryBuilder};

pub(in crate::mysql) async fn insert(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    record: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    execute_insert(connection, &model, record.clone()).await?;
    locate_inserted(connection, schema, model_name, &model, record).await
}

pub(in crate::mysql) async fn insert_required(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    record: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    insert(connection, schema, model_name, record)
        .await?
        .ok_or_else(|| AuthError::Storage(format!(
            "MySQL inserted '{model_name}' but could not identify the stored row"
        )))
}

async fn execute_insert(
    connection: &mut MySqlConnection,
    model: &crate::mysql::schema::MySqlModel<'_>,
    record: Map<String, Value>,
) -> Result<(), AuthError> {
    let writes = model.encode_fields(record)?;
    let mut query = QueryBuilder::<MySql>::new("insert into ");
    query.push(model.quoted_table());
    if writes.is_empty() {
        query.push(" () values ()");
    } else {
        query.push(" (");
        for (position, write) in writes.iter().enumerate() {
            if position > 0 { query.push(", "); }
            query.push(&write.quoted_column);
        }
        query.push(") values (");
        for (position, write) in writes.into_iter().enumerate() {
            if position > 0 { query.push(", "); }
            write.value.push_bind(&mut query);
        }
        query.push(")");
    }
    query.build().execute(connection).await.map_err(storage)?;
    Ok(())
}

async fn locate_inserted(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    model: &crate::mysql::schema::MySqlModel<'_>,
    record: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    if let Some(id) = record.get("id").filter(|value| truthy(value)) {
        return find_by(connection, schema, model_name, "id", id.clone()).await;
    }
    if model.id_type() == DatabaseIdType::Serial {
        let id = sqlx::query_scalar::<_, u64>("select last_insert_id()")
            .fetch_one(&mut *connection).await.map_err(storage)?;
        if id != 0 {
            return find_by(connection, schema, model_name, "id", Value::String(id.to_string())).await;
        }
    }
    if let Some((field, value)) = model.first_unique_value(&record) {
        return find_by(connection, schema, model_name, field, value).await;
    }
    let filters = record.into_iter().map(|(field, value)| MySqlFilter::equal(field, value)).collect::<Vec<_>>();
    if !filters.is_empty() {
        let matches = find_many(connection, schema, model_name, &filters, &MySqlFindOptions { limit: Some(2), ..Default::default() }).await?;
        if matches.len() == 1 { return Ok(matches.into_iter().next()); }
    }
    tracing::warn!("[Kysely Adapter] Unable to safely identify the inserted \"{model_name}\" row on MySQL. Enable Better Auth ID generation or use generateId: \"serial\" for reliable behavior.");
    Ok(None)
}

async fn find_by(connection: &mut MySqlConnection, schema: &MySqlSchema, model: &str, field: &str, value: Value) -> Result<Option<Map<String, Value>>, AuthError> {
    find_one(connection, schema, model, &[MySqlFilter::equal(field, value)], &[]).await
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) | Value::Bool(true) => true,
    }
}

fn storage(error: sqlx::Error) -> AuthError { AuthError::Storage(error.to_string()) }
