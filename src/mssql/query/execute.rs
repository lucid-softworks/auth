use super::{MssqlFilter, MssqlFindOptions, MssqlSortDirection, predicate};
use crate::{
    AuthError,
    mssql::{
        adapter::MssqlClient,
        schema::{MssqlModel, MssqlSchema, MssqlWrite},
        statement::MssqlStatement,
    },
};
use serde_json::{Map, Value};
use tiberius::Row;

const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(in crate::mssql) async fn insert(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    record: Map<String, Value>,
    debug_logs: bool,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(record)?;
    let mut query = MssqlStatement::new("insert into ");
    query.push(model.quoted_table());
    if writes.is_empty() {
        query
            .push(" output ")
            .push(model.all_projection_for("inserted"))
            .push(" default values");
    } else {
        query.push(" (");
        for (position, write) in writes.iter().enumerate() {
            if position > 0 {
                query.push(", ");
            }
            query.push(&write.quoted_column);
        }
        query
            .push(") output ")
            .push(model.all_projection_for("inserted"))
            .push(" values (");
        for (position, write) in writes.into_iter().enumerate() {
            if position > 0 {
                query.push(", ");
            }
            query.bind(write.value);
        }
        query.push(")");
    }
    query
        .query(connection, debug_logs)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

pub(in crate::mssql) async fn find_one(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    select: &[String],
    debug_logs: bool,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let projection = if select.is_empty() {
        model.all_projection()
    } else {
        model.projection(select.iter().map(String::as_str))?
    };
    let mut query = MssqlStatement::new("select top (1) ");
    query
        .push(projection)
        .push(" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .query(connection, debug_logs)
        .await?
        .into_iter()
        .next()
        .map(|row| decode_row(&model, &row, select))
        .transpose()
}

pub(in crate::mssql) async fn find_many(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    options: &MssqlFindOptions,
    debug_logs: bool,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let projection = if options.select.is_empty() {
        model.all_projection()
    } else {
        model.projection(options.select.iter().map(String::as_str))?
    };
    let mut query = MssqlStatement::new("select ");
    if options.offset.is_none()
        && let Some(limit) = options.limit.filter(|limit| *limit > 0)
    {
        query.push("top (").bind(integer_parameter(limit)?).push(") ");
    }
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
                MssqlSortDirection::Ascending => " asc",
                MssqlSortDirection::Descending => " desc",
            });
    } else if options.offset.is_some() {
        query.push(" order by [id] asc");
    }
    if let Some(offset) = options.offset {
        query
            .push(" offset ")
            .bind(integer_parameter(offset)?)
            .push(" rows fetch next ")
            .bind(integer_parameter(options.limit.unwrap_or(100).max(1))?)
            .push(" rows only");
    }
    query
        .query(connection, debug_logs)
        .await?
        .into_iter()
        .map(|row| decode_row(&model, &row, &options.select))
        .collect()
}

pub(in crate::mssql) async fn update_one(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    values: Map<String, Value>,
    debug_logs: bool,
) -> Result<Option<Map<String, Value>>, AuthError> {
    if filters.is_empty() {
        return Ok(None);
    }
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(values)?;
    if writes.is_empty() {
        return find_one(
            connection,
            schema,
            model_name,
            filters,
            &[],
            debug_logs,
        )
        .await;
    }
    let mut query = MssqlStatement::new("update ");
    query.push(model.quoted_table()).push(" set ");
    push_writes(&mut query, writes);
    query
        .push(" output ")
        .push(model.all_projection_for("inserted"));
    predicate::push(&mut query, &model, filters)?;
    query
        .query(connection, debug_logs)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

pub(in crate::mssql) async fn update_many(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    values: Map<String, Value>,
    debug_logs: bool,
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(values)?;
    if writes.is_empty() {
        return Ok(0);
    }
    let mut query = MssqlStatement::new("update ");
    query.push(model.quoted_table()).push(" set ");
    push_writes(&mut query, writes);
    predicate::push(&mut query, &model, filters)?;
    query
        .execute(connection, debug_logs)
        .await
        .map(clamp_affected)
}

pub(in crate::mssql) async fn count(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    debug_logs: bool,
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = MssqlStatement::new("select count([id]) as [count] from ");
    query.push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    let row = query
        .query(connection, debug_logs)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::Storage("MSSQL count returned no row".into()))?;
    row.try_get::<i32, _>("count")
        .map(|value| value.unwrap_or(0) as u64)
        .map_err(storage)
}

pub(in crate::mssql) async fn delete_many(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    debug_logs: bool,
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = MssqlStatement::new("delete from ");
    query.push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .execute(connection, debug_logs)
        .await
        .map(clamp_affected)
}

pub(in crate::mssql) async fn consume_one(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    debug_logs: bool,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = MssqlStatement::new("delete top (1) from ");
    query
        .push(model.quoted_table())
        .push(" output ")
        .push(model.all_projection_for("deleted"));
    predicate::push(&mut query, &model, filters)?;
    query
        .query(connection, debug_logs)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

pub(in crate::mssql) async fn increment_one(
    connection: &mut MssqlClient,
    schema: &MssqlSchema,
    model_name: &str,
    filters: &[MssqlFilter],
    increments: Map<String, Value>,
    mut set: Map<String, Value>,
    debug_logs: bool,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    for field in increments.keys() {
        set.remove(field);
    }
    if set.is_empty() && increments.is_empty() {
        return find_one(
            connection,
            schema,
            model_name,
            filters,
            &[],
            debug_logs,
        )
        .await;
    }
    let mut query = MssqlStatement::new("update top (1) ");
    query.push(model.quoted_table()).push(" set ");
    let mut position = 0;
    for (field, value) in set {
        separator(&mut query, &mut position);
        query
            .push(model.quoted_column(&field)?)
            .push(" = ")
            .bind(model.encode(&field, value)?);
    }
    for (field, delta) in increments {
        separator(&mut query, &mut position);
        let column = model.quoted_column(&field)?;
        query
            .push(column)
            .push(" = ")
            .push(column)
            .push(" + ")
            .bind(model.encode(&field, delta)?);
    }
    query
        .push(" output ")
        .push(model.all_projection_for("inserted"));
    predicate::push(&mut query, &model, filters)?;
    query
        .query(connection, debug_logs)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

fn decode_row(
    model: &MssqlModel<'_>,
    row: &Row,
    select: &[String],
) -> Result<Map<String, Value>, AuthError> {
    if select.is_empty() {
        return model.decode_all(row);
    }
    let mut result = Map::new();
    for field in select {
        let value = if field == "id" {
            crate::mssql::value::decode_id(row, field, model.id_type())?
        } else {
            let (kind, bigint, reference) = model.field_type(field)?;
            crate::mssql::value::decode(row, field, kind, bigint, reference)?
        };
        result.insert(field.clone(), value);
    }
    Ok(result)
}

fn push_writes(query: &mut MssqlStatement, writes: Vec<MssqlWrite>) {
    for (position, write) in writes.into_iter().enumerate() {
        if position > 0 {
            query.push(", ");
        }
        query
            .push(write.quoted_column)
            .push(" = ")
            .bind(write.value);
    }
}

fn separator(query: &mut MssqlStatement, position: &mut usize) {
    if *position > 0 {
        query.push(", ");
    }
    *position += 1;
}

fn integer_parameter(value: u64) -> Result<crate::mssql::value::MssqlValue, AuthError> {
    i64::try_from(value)
        .map(|value| crate::mssql::value::MssqlValue::Integer(Some(value)))
        .map_err(|_| AuthError::InvalidConfiguration("MSSQL pagination exceeds i64".into()))
}

fn clamp_affected(value: u64) -> u64 {
    value.min(JAVASCRIPT_MAX_SAFE_INTEGER)
}

fn storage(error: tiberius::error::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_bulk_mutations_at_the_javascript_boundary() {
        assert_eq!(
            clamp_affected(JAVASCRIPT_MAX_SAFE_INTEGER + 9),
            JAVASCRIPT_MAX_SAFE_INTEGER
        );
    }
}
