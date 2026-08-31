use super::{MySqlComparisonMode, MySqlFilter, MySqlFilterConnector, MySqlFilterOperator};
use crate::{AuthError, mysql::schema::MySqlModel};
use serde_json::Value;
use sqlx::{QueryBuilder, MySql};

pub(super) fn push(
    query: &mut QueryBuilder<'_, MySql>,
    model: &MySqlModel<'_>,
    filters: &[MySqlFilter],
) -> Result<(), AuthError> {
    let and = filters
        .iter()
        .filter(|filter| filter.connector == MySqlFilterConnector::And)
        .collect::<Vec<_>>();
    let or = filters
        .iter()
        .filter(|filter| filter.connector == MySqlFilterConnector::Or)
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
    query: &mut QueryBuilder<'_, MySql>,
    model: &MySqlModel<'_>,
    filters: &[&MySqlFilter],
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
    query: &mut QueryBuilder<'_, MySql>,
    model: &MySqlModel<'_>,
    filter: &MySqlFilter,
) -> Result<(), AuthError> {
    let column = model.quoted_column(&filter.field)?;
    let insensitive = filter.mode == MySqlComparisonMode::Insensitive
        && (filter.value.is_string()
            || filter
                .value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)));
    match filter.operator {
        MySqlFilterOperator::In | MySqlFilterOperator::NotIn => {
            push_set(query, model, filter, column, insensitive)?;
        }
        MySqlFilterOperator::Contains
        | MySqlFilterOperator::StartsWith
        | MySqlFilterOperator::EndsWith => {
            push_pattern(query, filter, column, insensitive)?;
        }
        MySqlFilterOperator::Eq | MySqlFilterOperator::Ne if filter.value.is_null() => {
            push_null(query, filter.operator, column);
        }
        operator => push_scalar(query, model, filter, column, insensitive, operator)?,
    }
    Ok(())
}

fn push_set(
    query: &mut QueryBuilder<'_, MySql>,
    model: &MySqlModel<'_>,
    filter: &MySqlFilter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    let values = filter
        .value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![filter.value.clone()]);
    if values.is_empty() {
        query.push(if filter.operator == MySqlFilterOperator::In {
            "0 = 1"
        } else {
            "1 = 1"
        });
        return Ok(());
    }
    push_column(query, column, insensitive);
    query.push(if filter.operator == MySqlFilterOperator::In {
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
    query: &mut QueryBuilder<'_, MySql>,
    filter: &MySqlFilter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    let value = filter.value.as_str().ok_or_else(|| {
        AuthError::InvalidConfiguration("MySQL pattern predicates require a string".into())
    })?;
    let pattern = match filter.operator {
        MySqlFilterOperator::Contains => format!("%{value}%"),
        MySqlFilterOperator::StartsWith => format!("{value}%"),
        MySqlFilterOperator::EndsWith => format!("%{value}"),
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

fn push_null(query: &mut QueryBuilder<'_, MySql>, operator: MySqlFilterOperator, column: &str) {
    query
        .push(column)
        .push(if operator == MySqlFilterOperator::Eq {
            " is null"
        } else {
            " is not null"
        });
}

fn push_scalar(
    query: &mut QueryBuilder<'_, MySql>,
    model: &MySqlModel<'_>,
    filter: &MySqlFilter,
    column: &str,
    insensitive: bool,
    operator: MySqlFilterOperator,
) -> Result<(), AuthError> {
    push_column(query, column, insensitive);
    query.push(match operator {
        MySqlFilterOperator::Eq => " = ",
        MySqlFilterOperator::Ne => " <> ",
        MySqlFilterOperator::Gt => " > ",
        MySqlFilterOperator::Gte => " >= ",
        MySqlFilterOperator::Lt => " < ",
        MySqlFilterOperator::Lte => " <= ",
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

fn push_column(query: &mut QueryBuilder<'_, MySql>, column: &str, insensitive: bool) {
    if insensitive {
        query.push("lower(").push(column).push(")");
    } else {
        query.push(column);
    }
}
