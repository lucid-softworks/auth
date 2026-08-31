mod atomic;
mod insert;

pub(in crate::mysql) use atomic::{
    consume_latest, consume_one, consume_one_in_transaction, increment_one,
    increment_one_in_transaction,
};
pub(in crate::mysql) use insert::{insert, insert_required};

use super::{MySqlFilter, MySqlFilterConnector, MySqlFilterOperator, MySqlFindOptions, MySqlSortDirection, predicate};
use crate::{AuthError, mysql::schema::MySqlSchema};
use serde_json::{Map, Value};
use sqlx::{MySql, MySqlConnection, QueryBuilder, Row};

const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(in crate::mysql) async fn find_one(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    select: &[String],
) -> Result<Option<Map<String, Value>>, AuthError> {
    find_one_with_lock(connection, schema, model_name, filters, select, false).await
}

pub(in crate::mysql) async fn find_one_for_update(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    select: &[String],
) -> Result<Option<Map<String, Value>>, AuthError> {
    find_one_with_lock(connection, schema, model_name, filters, select, true).await
}

async fn find_one_with_lock(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    select: &[String],
    for_update: bool,
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
    if for_update {
        query.push(" for update");
    }
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
    find_many_with_lock(connection, schema, model_name, filters, options, false).await
}

pub(in crate::mysql) async fn find_many_for_update(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    options: &MySqlFindOptions,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    find_many_with_lock(connection, schema, model_name, filters, options, true).await
}

async fn find_many_with_lock(
    connection: &mut MySqlConnection,
    schema: &MySqlSchema,
    model_name: &str,
    filters: &[MySqlFilter],
    options: &MySqlFindOptions,
    for_update: bool,
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
    if for_update {
        query.push(" for update");
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
        .try_get::<i64, _>("count")
        .map(|count| count as u64)
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

fn clamp_affected(value: u64) -> u64 {
    value.min(JAVASCRIPT_MAX_SAFE_INTEGER)
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
