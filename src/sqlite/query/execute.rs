use super::{SqliteFilter, SqliteFindOptions, SqliteSortDirection, predicate};
use crate::{AuthError, sqlite::schema::SqliteSchema};
use serde_json::{Map, Value};
use sqlx::{QueryBuilder, Row, Sqlite, SqliteConnection};

pub(in crate::sqlite) async fn insert(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    record: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(record)?;
    let mut query = QueryBuilder::<Sqlite>::new("insert into ");
    query.push(model.quoted_table());
    if writes.is_empty() {
        query.push(" default values");
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
    query.push(" returning ").push(model.all_projection());
    let row = query.build().fetch_one(connection).await.map_err(storage)?;
    model.decode_all(&row)
}

pub(in crate::sqlite) async fn find_one(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
    select: &[String],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let projection = if select.is_empty() {
        model.all_projection()
    } else {
        model.projection(select.iter().map(String::as_str))?
    };
    let mut query = QueryBuilder::<Sqlite>::new("select ");
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

pub(in crate::sqlite) async fn find_many(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
    options: &SqliteFindOptions,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let projection = if options.select.is_empty() {
        model.all_projection()
    } else {
        model.projection(options.select.iter().map(String::as_str))?
    };
    let mut query = QueryBuilder::<Sqlite>::new("select ");
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
                SqliteSortDirection::Ascending => " asc",
                SqliteSortDirection::Descending => " desc",
            });
    }
    if let Some(limit) = options.limit {
        query.push(" limit ").push_bind(limit as i64);
    } else if options.offset.is_some() {
        query.push(" limit -1");
    }
    if let Some(offset) = options.offset {
        query.push(" offset ").push_bind(offset as i64);
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

pub(in crate::sqlite) async fn update_one(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
    values: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    if filters.is_empty() {
        return Ok(None);
    }
    update_returning(connection, schema, model_name, filters, values).await
}

async fn update_returning(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
    values: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(values)?;
    if writes.is_empty() {
        return find_one(connection, schema, model_name, filters, &[]).await;
    }
    let mut query = QueryBuilder::<Sqlite>::new("update ");
    query.push(model.quoted_table()).push(" set ");
    push_writes(&mut query, writes);
    predicate::push(&mut query, &model, filters)?;
    query.push(" returning ").push(model.all_projection());
    let row = query
        .build()
        .fetch_optional(connection)
        .await
        .map_err(storage)?;
    row.map(|row| model.decode_all(&row)).transpose()
}

pub(in crate::sqlite) async fn update_many(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
    values: Map<String, Value>,
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(values)?;
    if writes.is_empty() {
        return Ok(0);
    }
    let mut query = QueryBuilder::<Sqlite>::new("update ");
    query.push(model.quoted_table()).push(" set ");
    push_writes(&mut query, writes);
    predicate::push(&mut query, &model, filters)?;
    query
        .build()
        .execute(connection)
        .await
        .map(|result| result.rows_affected())
        .map_err(storage)
}

pub(in crate::sqlite) async fn count(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = QueryBuilder::<Sqlite>::new("select count(\"id\") as \"count\" from ");
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

pub(in crate::sqlite) async fn delete_many(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = QueryBuilder::<Sqlite>::new("delete from ");
    query.push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .build()
        .execute(connection)
        .await
        .map(|result| result.rows_affected())
        .map_err(storage)
}

pub(in crate::sqlite) async fn consume_one(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = QueryBuilder::<Sqlite>::new("delete from ");
    query
        .push(model.quoted_table())
        .push(" where \"id\" in (select \"id\" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .push(" limit 1) returning ")
        .push(model.all_projection());
    let row = query
        .build()
        .fetch_optional(connection)
        .await
        .map_err(storage)?;
    row.map(|row| model.decode_all(&row)).transpose()
}

pub(in crate::sqlite) async fn consume_latest(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
    sort_field: &str,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = QueryBuilder::<Sqlite>::new("delete from ");
    query
        .push(model.quoted_table())
        .push(" where \"id\" in (select \"id\" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .push(" order by ")
        .push(model.quoted_column(sort_field)?)
        .push(" desc, \"id\" desc limit 1) returning ")
        .push(model.all_projection());
    let row = query
        .build()
        .fetch_optional(connection)
        .await
        .map_err(storage)?;
    row.map(|row| model.decode_all(&row)).transpose()
}

pub(in crate::sqlite) async fn increment_one(
    connection: &mut SqliteConnection,
    schema: &SqliteSchema,
    model_name: &str,
    filters: &[SqliteFilter],
    increments: Map<String, Value>,
    set: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = QueryBuilder::<Sqlite>::new("update ");
    query.push(model.quoted_table()).push(" set ");
    let mut assignments = 0;
    for (field, value) in set {
        if assignments > 0 {
            query.push(", ");
        }
        query.push(model.quoted_column(&field)?).push(" = ");
        model.encode(&field, value)?.push_bind(&mut query);
        assignments += 1;
    }
    for (field, delta) in increments {
        if assignments > 0 {
            query.push(", ");
        }
        let column = model.quoted_column(&field)?;
        query.push(column).push(" = ").push(column).push(" + ");
        model.encode(&field, delta)?.push_bind(&mut query);
        assignments += 1;
    }
    if assignments == 0 {
        return find_one(connection, schema, model_name, filters, &[]).await;
    }
    predicate::push(&mut query, &model, filters)?;
    query
        .push(if filters.is_empty() {
            " where "
        } else {
            " and "
        })
        .push("\"id\" in (select \"id\" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .push(" limit 1) returning ")
        .push(model.all_projection());
    let row = query
        .build()
        .fetch_optional(connection)
        .await
        .map_err(storage)?;
    row.map(|row| model.decode_all(&row)).transpose()
}

fn decode_selection(
    model: &crate::sqlite::schema::SqliteModel<'_>,
    row: &sqlx::sqlite::SqliteRow,
    select: &[String],
) -> Result<Map<String, Value>, AuthError> {
    let mut result = Map::new();
    for field in select {
        let value = if field == "id" {
            crate::sqlite::value::decode_id(row, field, model.id_type())?
        } else {
            let (kind, bigint, reference) = model.field_type(field)?;
            crate::sqlite::value::decode(row, field, kind, bigint, reference)?
        };
        result.insert(field.clone(), value);
    }
    Ok(result)
}

fn push_writes(
    query: &mut QueryBuilder<'_, Sqlite>,
    writes: Vec<crate::sqlite::schema::SqliteWrite>,
) {
    for (position, write) in writes.into_iter().enumerate() {
        if position > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column).push(" = ");
        write.value.push_bind(query);
    }
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
