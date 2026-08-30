use super::{SqliteComparisonMode, SqliteFilter, SqliteFilterConnector, SqliteFilterOperator};
use crate::{AuthError, sqlite::schema::SqliteModel};
use serde_json::Value;
use sqlx::{QueryBuilder, Sqlite};

pub(super) fn push(
    query: &mut QueryBuilder<'_, Sqlite>,
    model: &SqliteModel<'_>,
    filters: &[SqliteFilter],
) -> Result<(), AuthError> {
    let and = filters
        .iter()
        .filter(|filter| filter.connector == SqliteFilterConnector::And)
        .collect::<Vec<_>>();
    let or = filters
        .iter()
        .filter(|filter| filter.connector == SqliteFilterConnector::Or)
        .collect::<Vec<_>>();
    if and.is_empty() && or.is_empty() {
        return Ok(());
    }
    query.push(" where ");
    if !and.is_empty() {
        push_group(query, model, &and, " and ")?;
    }
    if !and.is_empty() && !or.is_empty() {
        query.push(" and ");
    }
    if !or.is_empty() {
        push_group(query, model, &or, " or ")?;
    }
    Ok(())
}

fn push_group(
    query: &mut QueryBuilder<'_, Sqlite>,
    model: &SqliteModel<'_>,
    filters: &[&SqliteFilter],
    separator: &str,
) -> Result<(), AuthError> {
    query.push("(");
    for (position, filter) in filters.iter().enumerate() {
        if position > 0 {
            query.push(separator);
        }
        push_filter(query, model, filter)?;
    }
    query.push(")");
    Ok(())
}

fn push_filter(
    query: &mut QueryBuilder<'_, Sqlite>,
    model: &SqliteModel<'_>,
    filter: &SqliteFilter,
) -> Result<(), AuthError> {
    let column = model.quoted_column(&filter.field)?;
    let insensitive = filter.mode == SqliteComparisonMode::Insensitive
        && (filter.value.is_string()
            || filter
                .value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)));
    match filter.operator {
        SqliteFilterOperator::In | SqliteFilterOperator::NotIn => {
            push_set(query, model, filter, column, insensitive)?;
        }
        SqliteFilterOperator::Contains
        | SqliteFilterOperator::StartsWith
        | SqliteFilterOperator::EndsWith => {
            push_pattern(query, filter, column, insensitive)?;
        }
        SqliteFilterOperator::Eq | SqliteFilterOperator::Ne if filter.value.is_null() => {
            push_null(query, filter.operator, column);
        }
        operator => push_scalar(query, model, filter, column, insensitive, operator)?,
    }
    Ok(())
}

fn push_set(
    query: &mut QueryBuilder<'_, Sqlite>,
    model: &SqliteModel<'_>,
    filter: &SqliteFilter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    let values = filter
        .value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![filter.value.clone()]);
    if values.is_empty() {
        query.push(if filter.operator == SqliteFilterOperator::In {
            "0 = 1"
        } else {
            "1 = 1"
        });
        return Ok(());
    }
    push_column(query, column, insensitive);
    query.push(if filter.operator == SqliteFilterOperator::In {
        " in ("
    } else {
        " not in ("
    });
    for (position, value) in values.into_iter().enumerate() {
        if position > 0 {
            query.push(", ");
        }
        let value = normalize_case(value, insensitive, "insensitive IN values are strings");
        model.encode(&filter.field, value)?.push_bind(query);
    }
    query.push(")");
    Ok(())
}

fn push_pattern(
    query: &mut QueryBuilder<'_, Sqlite>,
    filter: &SqliteFilter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    let value = filter.value.as_str().ok_or_else(|| {
        AuthError::InvalidConfiguration("SQLite pattern predicates require a string".into())
    })?;
    let pattern = match filter.operator {
        SqliteFilterOperator::Contains => format!("%{value}%"),
        SqliteFilterOperator::StartsWith => format!("{value}%"),
        SqliteFilterOperator::EndsWith => format!("%{value}"),
        _ => unreachable!(),
    };
    push_column(query, column, insensitive);
    query.push(" like ");
    if insensitive {
        query.push("lower(");
    }
    query.push_bind(pattern);
    if insensitive {
        query.push(")");
    }
    Ok(())
}

fn push_null(query: &mut QueryBuilder<'_, Sqlite>, operator: SqliteFilterOperator, column: &str) {
    query
        .push(column)
        .push(if operator == SqliteFilterOperator::Eq {
            " is null"
        } else {
            " is not null"
        });
}

fn push_scalar(
    query: &mut QueryBuilder<'_, Sqlite>,
    model: &SqliteModel<'_>,
    filter: &SqliteFilter,
    column: &str,
    insensitive: bool,
    operator: SqliteFilterOperator,
) -> Result<(), AuthError> {
    push_column(query, column, insensitive);
    query.push(match operator {
        SqliteFilterOperator::Eq => " = ",
        SqliteFilterOperator::Ne => " <> ",
        SqliteFilterOperator::Gt => " > ",
        SqliteFilterOperator::Gte => " >= ",
        SqliteFilterOperator::Lt => " < ",
        SqliteFilterOperator::Lte => " <= ",
        _ => unreachable!(),
    });
    let value = normalize_case(
        filter.value.clone(),
        insensitive,
        "insensitive scalar is a string",
    );
    model.encode(&filter.field, value)?.push_bind(query);
    Ok(())
}

fn normalize_case(value: Value, insensitive: bool, message: &str) -> Value {
    if insensitive {
        Value::String(value.as_str().expect(message).to_lowercase())
    } else {
        value
    }
}

fn push_column(query: &mut QueryBuilder<'_, Sqlite>, column: &str, insensitive: bool) {
    if insensitive {
        query.push("lower(").push(column).push(")");
    } else {
        query.push(column);
    }
}
