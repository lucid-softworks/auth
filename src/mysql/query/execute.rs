use super::{MySqlFilter, MySqlFilterConnector, MySqlFilterOperator, MySqlFindOptions, MySqlSortDirection, predicate};
use crate::{AuthError, DatabaseIdType, mysql::schema::MySqlSchema};
use serde_json::{Map, Value};
use sqlx::{Connection, MySql, MySqlConnection, QueryBuilder, Row, Transaction};

const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(in crate::mysql) async fn insert(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    record: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(record.clone())?;
    let mut query = QueryBuilder::<MySql>::new("insert into ");
    query.push(model.quoted_table());
    if writes.is_empty() {
        query.push(" () values ()");
    } else {
        query.push(" (");
        for (position, write) in writes.iter().enumerate() {
            if position > 0 {
                query.push(", ");
            }
            query.push(&write.quoted_column);
        }
        query.push(") values (");
        for (position, write) in writes.into_iter().enumerate() {
            if position > 0 {
                query.push(", ");
            }
            write.value.push_bind(&mut query);
        }
        query.push(")");
    }
    query.build().execute(&mut *connection).await.map_err(storage)?;

    if let Some(id) = record.get("id").filter(|value| truthy(value)) {
        return find_one(
            connection,
            schema,
            model_name,
            &[MySqlFilter::equal("id", id.clone())],
            &[],
        )
        .await;
    }
    if model.id_type() == DatabaseIdType::Serial {
        let id = sqlx::query_scalar::<_, u64>("select last_insert_id()")
            .fetch_one(&mut *connection)
            .await
            .map_err(storage)?;
        if id != 0 {
            return find_one(
                connection,
                schema,
                model_name,
                &[MySqlFilter::equal("id", Value::String(id.to_string()))],
                &[],
            )
            .await;
        }
    }
    if let Some((field, value)) = model.first_unique_value(&record) {
        return find_one(
            connection,
            schema,
            model_name,
            &[MySqlFilter::equal(field, value)],
            &[],
        )
        .await;
    }
    let filters = record
        .into_iter()
        .map(|(field, value)| MySqlFilter::equal(field, value))
        .collect::<Vec<_>>();
    if !filters.is_empty() {
        let matches = find_many(
            connection,
            schema,
            model_name,
            &filters,
            &MySqlFindOptions {
                limit: Some(2),
                ..MySqlFindOptions::default()
            },
        )
        .await?;
        if matches.len() == 1 {
            return Ok(matches.into_iter().next());
        }
    }
    tracing::warn!(
        "[Kysely Adapter] Unable to safely identify the inserted \"{model_name}\" row on MySQL. Enable Better Auth ID generation or use generateId: \"serial\" for reliable behavior."
    );
    Ok(None)
}

pub(in crate::mysql) async fn find_one(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    select: &[String],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let projection = if select.is_empty() {
        model.all_projection()
    } else {
        model.projection(select.iter().map(String::as_str))?
    };
    let mut query = QueryBuilder::<MySql>::new("select ");
    query
        .push(projection)
        .push(" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query.push(" limit 1");
    let Some(row) = query
        .build()
        .fetch_optional(connection)
        .await
        .map_err(storage)?
    else {
        return Ok(None);
    };
    if select.is_empty() {
        model.decode_all(&row).map(Some)
    } else {
        decode_selection(&model, &row, select).map(Some)
    }
}

pub(in crate::mysql) async fn find_many(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    options: &MySqlFindOptions,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let projection = if options.select.is_empty() {
        model.all_projection()
    } else {
        model.projection(options.select.iter().map(String::as_str))?
    };
    let mut query = QueryBuilder::<MySql>::new("select ");
    query
        .push(projection)
        .push(" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    if let Some(sort) = &options.sort {
        query
            .push(" order by ")
            .push(model.quoted_column(&sort.field)?)
            .push(match sort.direction {
                MySqlSortDirection::Ascending => " asc",
                MySqlSortDirection::Descending => " desc",
            });
    }
    if let Some(limit) = options.limit {
        query.push(" limit ").push_bind(limit);
    } else if options.offset.is_some() {
        query.push(" limit 18446744073709551615");
    }
    if let Some(offset) = options.offset {
        query.push(" offset ").push_bind(offset);
    }
    let rows = query.build().fetch_all(connection).await.map_err(storage)?;
    if options.select.is_empty() {
        rows.into_iter().map(|row| model.decode_all(&row)).collect()
    } else {
        rows.into_iter()
            .map(|row| decode_selection(&model, &row, &options.select))
            .collect()
    }
}

pub(in crate::mysql) async fn update_one(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    values: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    if filters.is_empty() {
        return Ok(None);
    }
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(values.clone())?;
    if writes.is_empty() {
        return find_one(connection, schema, model_name, filters, &[]).await;
    }
    let mut query = QueryBuilder::<MySql>::new("update ");
    query.push(model.quoted_table()).push(" set ");
    push_writes(&mut query, writes);
    predicate::push(&mut query, &model, filters)?;
    let affected = query
        .build()
        .execute(&mut *connection)
        .await
        .map_err(storage)?
        .rows_affected();
    if affected == 0 {
        return Ok(None);
    }
    let lookup = update_lookup(filters, &values)?;
    find_one(connection, schema, model_name, &[lookup], &[]).await
}

pub(in crate::mysql) async fn update_many(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    values: Map<String, Value>,
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(values)?;
    if writes.is_empty() {
        return Ok(0);
    }
    let mut query = QueryBuilder::<MySql>::new("update ");
    query.push(model.quoted_table()).push(" set ");
    push_writes(&mut query, writes);
    predicate::push(&mut query, &model, filters)?;
    query
        .build()
        .execute(connection)
        .await
        .map(|result| clamp_affected(result.rows_affected()))
        .map_err(storage)
}

pub(in crate::mysql) async fn count(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = QueryBuilder::<MySql>::new("select count(`id`) as `count` from ");
    query.push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .build()
        .fetch_one(connection)
        .await
        .map_err(storage)?
        .try_get::<u64, _>("count")
        .map_err(storage)
}

pub(in crate::mysql) async fn delete_many(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = QueryBuilder::<MySql>::new("delete from ");
    query.push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .build()
        .execute(connection)
        .await
        .map(|result| clamp_affected(result.rows_affected()))
        .map_err(storage)
}

pub(in crate::mysql) async fn consume_one(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let mut transaction = connection.begin().await.map_err(storage)?;
    let result = consume_one_in_transaction(&mut transaction, schema, model_name, filters).await;
    finish(transaction, result).await
}

pub(in crate::mysql) async fn consume_one_in_transaction(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut select = QueryBuilder::<MySql>::new("select ");
    select
        .push(model.all_projection())
        .push(" from ")
        .push(model.quoted_table());
    predicate::push(&mut select, &model, filters)?;
    select.push(" limit 1 for update");
    let Some(row) = select
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage)?
    else {
        return Ok(None);
    };
    let record = model.decode_all(&row)?;
    let id = record
        .get("id")
        .cloned()
        .ok_or_else(|| AuthError::Storage("locked MySQL row has no id".into()))?;
    let deleted = delete_many(
        transaction,
        schema,
        model_name,
        &[MySqlFilter::equal("id", id)],
    )
    .await?;
    Ok((deleted > 0).then_some(record))
}

pub(in crate::mysql) async fn increment_one(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    increments: Map<String, Value>,
    set: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let mut transaction = connection.begin().await.map_err(storage)?;
    let result = increment_one_in_transaction(
        &mut transaction,
        schema,
        model_name,
        filters,
        increments,
        set,
    )
    .await;
    finish(transaction, result).await
}

pub(in crate::mysql) async fn increment_one_in_transaction(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    increments: Map<String, Value>,
    mut set: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut select = QueryBuilder::<MySql>::new("select `id` as `id` from ");
    select.push(model.quoted_table());
    predicate::push(&mut select, &model, filters)?;
    select.push(" limit 1 for update");
    let Some(row) = select
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage)?
    else {
        return Ok(None);
    };
    let id = crate::mysql::value::decode_id(&row, "id", model.id_type())?;
    for field in increments.keys() {
        set.remove(field);
    }
    let mut update = QueryBuilder::<MySql>::new("update ");
    update.push(model.quoted_table()).push(" set ");
    let mut assignments = 0;
    for (field, value) in set {
        push_separator(&mut update, &mut assignments);
        update.push(model.quoted_column(&field)?).push(" = ");
        model.encode(&field, value)?.push_bind(&mut update);
    }
    for (field, delta) in increments {
        push_separator(&mut update, &mut assignments);
        let column = model.quoted_column(&field)?;
        update.push(column).push(" = ").push(column).push(" + ");
        model.encode(&field, delta)?.push_bind(&mut update);
    }
    if assignments == 0 {
        return find_one(
            transaction,
            schema,
            model_name,
            &[MySqlFilter::equal("id", id)],
            &[],
        )
        .await;
    }
    let mut exact_filters = filters.to_vec();
    exact_filters.push(MySqlFilter::equal("id", id.clone()));
    predicate::push(&mut update, &model, &exact_filters)?;
    let affected = update
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage)?
        .rows_affected();
    if affected == 0 {
        return Ok(None);
    }
    find_one(
        transaction,
        schema,
        model_name,
        &[MySqlFilter::equal("id", id)],
        &[],
    )
    .await
}

fn update_lookup(
    filters: &[MySqlFilter],
    values: &Map<String, Value>,
) -> Result<MySqlFilter, AuthError> {
    if let Some(id) = values.get("id").filter(|value| !value.is_null()) {
        return Ok(MySqlFilter::equal("id", id.clone()));
    }
    if let Some(filter) = filters.iter().find(|filter| {
        filter.field == "id"
            && filter.operator == MySqlFilterOperator::Eq
            && filter.connector != MySqlFilterConnector::Or
            && !filter.value.is_null()
    }) {
        return Ok(MySqlFilter::equal("id", filter.value.clone()));
    }
    let first = filters.first().ok_or_else(|| {
        AuthError::InvalidConfiguration("MySQL update lookup requires a predicate".into())
    })?;
    Ok(MySqlFilter::equal(
        first.field.clone(),
        values
            .get(&first.field)
            .cloned()
            .unwrap_or_else(|| first.value.clone()),
    ))
}

fn decode_selection(
    model: &crate::mysql::schema::MySqlModel<'_>,
    row: &sqlx::mysql::MySqlRow,
    select: &[String],
) -> Result<Map<String, Value>, AuthError> {
    let mut result = Map::new();
    for field in select {
        let value = if field == "id" {
            crate::mysql::value::decode_id(row, field, model.id_type())?
        } else {
            let (kind, bigint, reference) = model.field_type(field)?;
            crate::mysql::value::decode(row, field, kind, bigint, reference)?
        };
        result.insert(field.clone(), value);
    }
    Ok(result)
}

fn push_writes(
    query: &mut QueryBuilder<'_, MySql>,
    writes: Vec<crate::mysql::schema::MySqlWrite>,
) {
    for (position, write) in writes.into_iter().enumerate() {
        if position > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column).push(" = ");
        write.value.push_bind(query);
    }
}

fn push_separator(query: &mut QueryBuilder<'_, MySql>, assignments: &mut usize) {
    if *assignments > 0 {
        query.push(", ");
    }
    *assignments += 1;
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) | Value::Bool(true) => true,
    }
}

fn clamp_affected(value: u64) -> u64 {
    value.min(JAVASCRIPT_MAX_SAFE_INTEGER)
}

async fn finish<T>(
    transaction: Transaction<'_, MySql>,
    result: Result<T, AuthError>,
) -> Result<T, AuthError> {
    match result {
        Ok(value) => {
            transaction.commit().await.map_err(storage)?;
            Ok(value)
        }
        Err(error) => {
            if let Err(rollback) = transaction.rollback().await {
                tracing::warn!(error = %rollback, "failed to roll back MySQL adapter transaction");
            }
            Err(error)
        }
    }
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_reselection_uses_the_published_order() {
        let filters = vec![
            MySqlFilter {
                field: "email".into(),
                value: Value::String("old@example.com".into()),
                operator: MySqlFilterOperator::Contains,
                connector: MySqlFilterConnector::Or,
                mode: Default::default(),
            },
            MySqlFilter::equal("id", Value::String("row-id".into())),
        ];
        let mut values = Map::new();
        values.insert("email".into(), Value::String("new@example.com".into()));
        assert_eq!(update_lookup(&filters, &values).unwrap().field, "id");
        values.insert("id".into(), Value::String("new-id".into()));
        assert_eq!(
            update_lookup(&filters, &values).unwrap().value,
            Value::String("new-id".into())
        );
    }

    #[test]
    fn clamps_bulk_mutations_only_at_the_javascript_boundary() {
        assert_eq!(
            clamp_affected(JAVASCRIPT_MAX_SAFE_INTEGER + 9),
            JAVASCRIPT_MAX_SAFE_INTEGER
        );
    }
}
