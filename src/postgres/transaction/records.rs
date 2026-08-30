use super::{PostgresTransaction, closed_transaction};
use crate::{
    AuthError, DashAdapterConnector, DashAdapterOperator, DashAdapterSort, DashAdapterWhere,
    DashSortDirection,
};
use serde_json::{Map, Value};
use sqlx::{Postgres, QueryBuilder, Row};

pub(super) async fn find(
    transaction: &PostgresTransaction,
    model_name: &str,
    where_clause: &[DashAdapterWhere],
    limit: Option<usize>,
    offset: usize,
    sort: Option<&DashAdapterSort>,
    select: &[String],
) -> Result<Vec<Map<String, Value>>, AuthError> {
    transaction.ensure_active()?;
    let model = transaction.store.physical_model(model_name)?;
    let mut query = super::super::rows::select_query(&model);
    push_where(&mut query, &model, where_clause)?;
    if let Some(sort) = sort {
        query
            .push(" ORDER BY ")
            .push(model.quoted_column(&sort.field)?)
            .push(match sort.direction {
                DashSortDirection::Asc => " ASC",
                DashSortDirection::Desc => " DESC",
            });
    }
    if let Some(limit) = limit {
        query.push(" LIMIT ").push_bind(limit as i64);
    }
    if offset > 0 {
        query.push(" OFFSET ").push_bind(offset as i64);
    }
    let mut sql = transaction.sql.lock().await;
    let rows = query
        .build()
        .fetch_all(&mut **sql.as_mut().ok_or_else(closed_transaction)?)
        .await
        .map_err(super::super::storage_error)?;
    rows.into_iter()
        .map(|row| {
            let mut record = model.decode_all(&row)?;
            if !select.is_empty() {
                record.retain(|field, _| select.iter().any(|selected| selected == field));
            }
            Ok(record)
        })
        .collect()
}

pub(super) async fn create(
    transaction: &PostgresTransaction,
    model_name: &str,
    data: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    transaction.ensure_active()?;
    let model = transaction.store.physical_model(model_name)?;
    let writes = model.encode_fields(
        data.iter()
            .map(|(field, value)| (field.as_str(), value.clone())),
    )?;
    let mut query = super::super::rows::insert_query(&model, writes);
    let mut sql = transaction.sql.lock().await;
    let row = query
        .build()
        .fetch_one(&mut **sql.as_mut().ok_or_else(closed_transaction)?)
        .await
        .map_err(super::super::storage_error)?;
    model.decode_all(&row)
}

pub(super) async fn update(
    transaction: &PostgresTransaction,
    model_name: &str,
    where_clause: &[DashAdapterWhere],
    update: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    transaction.ensure_active()?;
    if where_clause.is_empty() {
        return Ok(None);
    }
    let model = transaction.store.physical_model(model_name)?;
    let writes = model.encode_fields(
        update
            .iter()
            .map(|(field, value)| (field.as_str(), value.clone())),
    )?;
    if writes.is_empty() {
        return find(transaction, model_name, where_clause, Some(1), 0, None, &[])
            .await
            .map(|mut rows| rows.pop());
    }
    let mut query = super::super::rows::update_query(&model, writes);
    push_first_id_fence(&mut query, &model, where_clause)?;
    query.push(" RETURNING ").push(model.all_projection());
    let mut sql = transaction.sql.lock().await;
    query
        .build()
        .fetch_optional(&mut **sql.as_mut().ok_or_else(closed_transaction)?)
        .await
        .map_err(super::super::storage_error)?
        .map(|row| model.decode_all(&row))
        .transpose()
}

pub(super) async fn delete(
    transaction: &PostgresTransaction,
    model_name: &str,
    where_clause: &[DashAdapterWhere],
) -> Result<u64, AuthError> {
    transaction.ensure_active()?;
    let model = transaction.store.physical_model(model_name)?;
    let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
    query.push(model.quoted_table());
    push_where(&mut query, &model, where_clause)?;
    let mut sql = transaction.sql.lock().await;
    query
        .build()
        .execute(&mut **sql.as_mut().ok_or_else(closed_transaction)?)
        .await
        .map(|result| result.rows_affected())
        .map_err(super::super::storage_error)
}

pub(super) async fn count(
    transaction: &PostgresTransaction,
    model_name: &str,
    where_clause: &[DashAdapterWhere],
) -> Result<u64, AuthError> {
    transaction.ensure_active()?;
    let model = transaction.store.physical_model(model_name)?;
    let mut query = QueryBuilder::<Postgres>::new("SELECT COUNT(\"id\") AS \"count\" FROM ");
    query.push(model.quoted_table());
    push_where(&mut query, &model, where_clause)?;
    let mut sql = transaction.sql.lock().await;
    let count = query
        .build()
        .fetch_one(&mut **sql.as_mut().ok_or_else(closed_transaction)?)
        .await
        .map_err(super::super::storage_error)?
        .try_get::<i64, _>("count")
        .map_err(super::super::storage_error)?;
    Ok(count as u64)
}

pub(super) async fn increment(
    transaction: &PostgresTransaction,
    model_name: &str,
    where_clause: &[DashAdapterWhere],
    increments: Map<String, Value>,
    set: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    transaction.ensure_active()?;
    if where_clause.is_empty() {
        return Ok(None);
    }
    if increments.is_empty() && set.is_empty() {
        return find(transaction, model_name, where_clause, Some(1), 0, None, &[])
            .await
            .map(|mut rows| rows.pop());
    }
    let model = transaction.store.physical_model(model_name)?;
    let mut query = QueryBuilder::<Postgres>::new("UPDATE ");
    query.push(model.quoted_table()).push(" SET ");
    let mut assignments = 0;
    for (field, value) in set {
        if assignments > 0 {
            query.push(", ");
        }
        query.push(model.quoted_column(&field)?).push(" = ");
        super::super::rows::push_model_value(&mut query, &model, &field, value)?;
        assignments += 1;
    }
    for (field, delta) in increments {
        if assignments > 0 {
            query.push(", ");
        }
        let column = model.quoted_column(&field)?;
        query.push(column).push(" = ").push(column).push(" + ");
        super::super::rows::push_model_value(&mut query, &model, &field, delta)?;
        assignments += 1;
    }
    push_first_id_fence(&mut query, &model, where_clause)?;
    query.push(" RETURNING ").push(model.all_projection());
    let mut sql = transaction.sql.lock().await;
    query
        .build()
        .fetch_optional(&mut **sql.as_mut().ok_or_else(closed_transaction)?)
        .await
        .map_err(super::super::storage_error)?
        .map(|row| model.decode_all(&row))
        .transpose()
}

fn push_first_id_fence(
    query: &mut QueryBuilder<'_, Postgres>,
    model: &super::super::PostgresModel<'_>,
    where_clause: &[DashAdapterWhere],
) -> Result<(), AuthError> {
    query
        .push(" WHERE \"id\" IN (SELECT \"id\" FROM ")
        .push(model.quoted_table());
    push_where(query, model, where_clause)?;
    query.push(" LIMIT 1)");
    Ok(())
}

fn push_where(
    query: &mut QueryBuilder<'_, Postgres>,
    model: &super::super::PostgresModel<'_>,
    where_clause: &[DashAdapterWhere],
) -> Result<(), AuthError> {
    let and = where_clause
        .iter()
        .filter(|condition| {
            condition.connector.unwrap_or(DashAdapterConnector::And) == DashAdapterConnector::And
        })
        .collect::<Vec<_>>();
    let or = where_clause
        .iter()
        .filter(|condition| condition.connector == Some(DashAdapterConnector::Or))
        .collect::<Vec<_>>();
    if and.is_empty() && or.is_empty() {
        return Ok(());
    }
    query.push(" WHERE ");
    if !and.is_empty() {
        push_group(query, model, &and, " AND ")?;
    }
    if !and.is_empty() && !or.is_empty() {
        query.push(" AND ");
    }
    if !or.is_empty() {
        push_group(query, model, &or, " OR ")?;
    }
    Ok(())
}

fn push_group(
    query: &mut QueryBuilder<'_, Postgres>,
    model: &super::super::PostgresModel<'_>,
    conditions: &[&DashAdapterWhere],
    separator: &str,
) -> Result<(), AuthError> {
    query.push("(");
    for (position, condition) in conditions.iter().enumerate() {
        if position > 0 {
            query.push(separator);
        }
        push_condition(query, model, condition)?;
    }
    query.push(")");
    Ok(())
}

fn push_condition(
    query: &mut QueryBuilder<'_, Postgres>,
    model: &super::super::PostgresModel<'_>,
    condition: &DashAdapterWhere,
) -> Result<(), AuthError> {
    let column = model.quoted_column(&condition.field)?;
    match condition.operator {
        DashAdapterOperator::Eq | DashAdapterOperator::Ne if condition.value.is_null() => {
            query.push(column).push(if condition.operator == DashAdapterOperator::Eq {
                " IS NULL"
            } else {
                " IS NOT NULL"
            });
        }
        DashAdapterOperator::In => push_set(query, model, condition, column)?,
        DashAdapterOperator::Contains
        | DashAdapterOperator::StartsWith
        | DashAdapterOperator::EndsWith => push_pattern(query, model, condition, column)?,
        operator => {
            query.push(column).push(match operator {
                DashAdapterOperator::Eq => " = ",
                DashAdapterOperator::Ne => " <> ",
                DashAdapterOperator::Gt => " > ",
                DashAdapterOperator::Gte => " >= ",
                DashAdapterOperator::Lt => " < ",
                DashAdapterOperator::Lte => " <= ",
                _ => unreachable!(),
            });
            super::super::rows::push_model_value(
                query,
                model,
                &condition.field,
                condition.value.clone(),
            )?;
        }
    }
    Ok(())
}

fn push_set(
    query: &mut QueryBuilder<'_, Postgres>,
    model: &super::super::PostgresModel<'_>,
    condition: &DashAdapterWhere,
    column: &str,
) -> Result<(), AuthError> {
    let values = condition
        .value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![condition.value.clone()]);
    if values.is_empty() {
        query.push("FALSE");
        return Ok(());
    }
    query.push(column).push(" IN (");
    for (position, value) in values.into_iter().enumerate() {
        if position > 0 {
            query.push(", ");
        }
        super::super::rows::push_model_value(query, model, &condition.field, value)?;
    }
    query.push(")");
    Ok(())
}

fn push_pattern(
    query: &mut QueryBuilder<'_, Postgres>,
    model: &super::super::PostgresModel<'_>,
    condition: &DashAdapterWhere,
    column: &str,
) -> Result<(), AuthError> {
    let value = condition.value.as_str().ok_or_else(|| {
        AuthError::InvalidConfiguration("PostgreSQL pattern predicates require a string".into())
    })?;
    let pattern = match condition.operator {
        DashAdapterOperator::Contains => format!("%{value}%"),
        DashAdapterOperator::StartsWith => format!("{value}%"),
        DashAdapterOperator::EndsWith => format!("%{value}"),
        _ => unreachable!(),
    };
    query.push(column).push(" LIKE ");
    super::super::rows::push_model_value(query, model, &condition.field, Value::String(pattern))?;
    Ok(())
}
