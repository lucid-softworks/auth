use super::{D1Filter, D1FindOptions, D1SortDirection, builder::Query, predicate};
use crate::{
    AuthError,
    d1::{D1Database, schema::D1Schema},
};
use serde_json::{Map, Value};

pub(in crate::d1) async fn insert(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    record: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(record)?;
    let mut query = Query::new("insert into ");
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
            query.bind(write.value);
        }
        query.push(")");
    }
    query.push(" returning ").push(&model.all_projection());
    let mut rows = all(database, query).await?;
    let row = rows
        .pop()
        .ok_or_else(|| AuthError::Storage("D1 insert returned no row".into()))?;
    model.decode_all(&row)
}

pub(in crate::d1) async fn find_one(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    filters: &[D1Filter],
    select: &[String],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let projection = if select.is_empty() {
        model.all_projection()
    } else {
        model.projection(select.iter().map(String::as_str))?
    };
    let mut query = Query::new("select ");
    query
        .push(&projection)
        .push(" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query.push(" limit 1");
    all(database, query)
        .await?
        .into_iter()
        .next()
        .map(|row| {
            if select.is_empty() {
                model.decode_all(&row)
            } else {
                model.decode_selection(&row, select)
            }
        })
        .transpose()
}

pub(in crate::d1) async fn find_many(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    filters: &[D1Filter],
    options: &D1FindOptions,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let projection = if options.select.is_empty() {
        model.all_projection()
    } else {
        model.projection(options.select.iter().map(String::as_str))?
    };
    let mut query = Query::new("select ");
    query
        .push(&projection)
        .push(" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    if let Some(sort) = &options.sort {
        query
            .push(" order by ")
            .push(model.quoted_column(&sort.field)?)
            .push(match sort.direction {
                D1SortDirection::Ascending => " asc",
                D1SortDirection::Descending => " desc",
            });
    }
    if let Some(limit) = options.limit {
        query
            .push(" limit ")
            .bind(crate::d1::D1Value::Integer(limit as i64));
    } else if options.offset.is_some() {
        query.push(" limit -1");
    }
    if let Some(offset) = options.offset {
        query
            .push(" offset ")
            .bind(crate::d1::D1Value::Integer(offset as i64));
    }
    all(database, query)
        .await?
        .into_iter()
        .map(|row| {
            if options.select.is_empty() {
                model.decode_all(&row)
            } else {
                model.decode_selection(&row, &options.select)
            }
        })
        .collect()
}

pub(in crate::d1) async fn update_one(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    filters: &[D1Filter],
    values: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    if filters.is_empty() {
        return Ok(None);
    }
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(values)?;
    if writes.is_empty() {
        return find_one(database, schema, model_name, filters, &[]).await;
    }
    let mut query = Query::new("update ");
    query.push(model.quoted_table()).push(" set ");
    push_writes(&mut query, writes);
    predicate::push(&mut query, &model, filters)?;
    query.push(" returning ").push(&model.all_projection());
    all(database, query)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

pub(in crate::d1) async fn update_many(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    filters: &[D1Filter],
    values: Map<String, Value>,
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let writes = model.encode_fields(values)?;
    if writes.is_empty() {
        return Ok(0);
    }
    let mut query = Query::new("update ");
    query.push(model.quoted_table()).push(" set ");
    push_writes(&mut query, writes);
    predicate::push(&mut query, &model, filters)?;
    changes(database, query).await
}

pub(in crate::d1) async fn count(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    filters: &[D1Filter],
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = Query::new("select count(\"id\") as \"count\" from ");
    query.push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    let row = all(database, query)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::Storage("D1 count returned no row".into()))?;
    row.get("count")
        .and_then(Value::as_u64)
        .ok_or_else(|| AuthError::Storage("D1 count result is invalid".into()))
}

pub(in crate::d1) async fn delete_many(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    filters: &[D1Filter],
) -> Result<u64, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = Query::new("delete from ");
    query.push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    changes(database, query).await
}

pub(in crate::d1) async fn consume_one(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    filters: &[D1Filter],
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = Query::new("delete from ");
    query
        .push(model.quoted_table())
        .push(" where \"id\" in (select \"id\" from ")
        .push(model.quoted_table());
    predicate::push(&mut query, &model, filters)?;
    query
        .push(" limit 1) returning ")
        .push(&model.all_projection());
    all(database, query)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

pub(in crate::d1) async fn increment_one(
    database: &dyn D1Database,
    schema: &D1Schema,
    model_name: &str,
    filters: &[D1Filter],
    increments: Map<String, Value>,
    set: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    let model = schema.model(model_name)?;
    let mut query = Query::new("update ");
    query.push(model.quoted_table()).push(" set ");
    let mut assignments = 0;
    for (field, value) in set {
        if assignments > 0 {
            query.push(", ");
        }
        query
            .push(model.quoted_column(&field)?)
            .push(" = ")
            .bind(model.encode(&field, value)?);
        assignments += 1;
    }
    for (field, delta) in increments {
        if assignments > 0 {
            query.push(", ");
        }
        let column = model.quoted_column(&field)?;
        query
            .push(column)
            .push(" = ")
            .push(column)
            .push(" + ")
            .bind(model.encode(&field, delta)?);
        assignments += 1;
    }
    if assignments == 0 {
        return find_one(database, schema, model_name, filters, &[]).await;
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
        .push(&model.all_projection());
    all(database, query)
        .await?
        .into_iter()
        .next()
        .map(|row| model.decode_all(&row))
        .transpose()
}

fn push_writes(query: &mut Query, writes: Vec<crate::d1::schema::D1Write>) {
    for (position, write) in writes.into_iter().enumerate() {
        if position > 0 {
            query.push(", ");
        }
        query
            .push(&write.quoted_column)
            .push(" = ")
            .bind(write.value);
    }
}

async fn all(
    database: &dyn D1Database,
    query: Query,
) -> Result<Vec<Map<String, Value>>, AuthError> {
    database
        .all(query.finish())
        .await
        .map(|result| result.results)
        .map_err(storage)
}

async fn changes(database: &dyn D1Database, query: Query) -> Result<u64, AuthError> {
    database
        .all(query.finish())
        .await
        .map(|result| result.changes.unwrap_or(0))
        .map_err(storage)
}

fn storage(error: crate::d1::D1TransportError) -> AuthError {
    AuthError::Storage(error.to_string())
}
