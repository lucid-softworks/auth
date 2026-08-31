use super::{MssqlComparisonMode, MssqlFilter, MssqlFilterConnector, MssqlFilterOperator};
use crate::{AuthError, mssql::schema::MssqlModel};
use serde_json::Value;

pub(super) fn push(
    query: &mut crate::mssql::statement::MssqlStatement,
    model: &MssqlModel<'_>,
    filters: &[MssqlFilter],
) -> Result<(), AuthError> {
    let and = filters
        .iter()
        .filter(|filter| filter.connector == MssqlFilterConnector::And)
        .collect::<Vec<_>>();
    let or = filters
        .iter()
        .filter(|filter| filter.connector == MssqlFilterConnector::Or)
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
    query: &mut crate::mssql::statement::MssqlStatement,
    model: &MssqlModel<'_>,
    filters: &[&MssqlFilter],
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
    query: &mut crate::mssql::statement::MssqlStatement,
    model: &MssqlModel<'_>,
    filter: &MssqlFilter,
) -> Result<(), AuthError> {
    let column = model.quoted_column(&filter.field)?;
    let insensitive = filter.mode == MssqlComparisonMode::Insensitive
        && (filter.value.is_string()
            || filter
                .value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)));
    match filter.operator {
        MssqlFilterOperator::In | MssqlFilterOperator::NotIn => {
            push_set(query, model, filter, column, insensitive)?;
        }
        MssqlFilterOperator::Contains
        | MssqlFilterOperator::StartsWith
        | MssqlFilterOperator::EndsWith => push_pattern(query, filter, column, insensitive)?,
        MssqlFilterOperator::Eq | MssqlFilterOperator::Ne if filter.value.is_null() => {
            push_null(query, filter.operator, column);
        }
        operator => push_scalar(query, model, filter, column, insensitive, operator)?,
    }
    Ok(())
}

fn push_set(
    query: &mut crate::mssql::statement::MssqlStatement,
    model: &MssqlModel<'_>,
    filter: &MssqlFilter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    let values = filter
        .value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![filter.value.clone()]);
    if values.is_empty() {
        query.push(if filter.operator == MssqlFilterOperator::In {
            "0 = 1"
        } else {
            "1 = 1"
        });
        return Ok(());
    }
    push_column(query, column, insensitive);
    query.push(if filter.operator == MssqlFilterOperator::In {
        " in ("
    } else {
        " not in ("
    });
    for (position, value) in values.into_iter().enumerate() {
        if position > 0 {
            query.push(", ");
        }
        let value = normalize_case(value, insensitive, "insensitive IN values are strings");
        query.bind(model.encode(&filter.field, value)?);
    }
    query.push(")");
    Ok(())
}

fn push_pattern(
    query: &mut crate::mssql::statement::MssqlStatement,
    filter: &MssqlFilter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    let value = filter.value.as_str().ok_or_else(|| {
        AuthError::InvalidConfiguration("MSSQL pattern predicates require a string".into())
    })?;
    let pattern = match filter.operator {
        MssqlFilterOperator::Contains => format!("%{value}%"),
        MssqlFilterOperator::StartsWith => format!("{value}%"),
        MssqlFilterOperator::EndsWith => format!("%{value}"),
        _ => unreachable!(),
    };
    push_column(query, column, insensitive);
    query.push(" like ");
    if insensitive {
        query.push("lower(");
    }
    query.bind(crate::mssql::value::MssqlValue::Text(Some(pattern)));
    if insensitive {
        query.push(")");
    }
    Ok(())
}

fn push_null(
    query: &mut crate::mssql::statement::MssqlStatement,
    operator: MssqlFilterOperator,
    column: &str,
) {
    query.push(column).push(if operator == MssqlFilterOperator::Eq {
        " is null"
    } else {
        " is not null"
    });
}

fn push_scalar(
    query: &mut crate::mssql::statement::MssqlStatement,
    model: &MssqlModel<'_>,
    filter: &MssqlFilter,
    column: &str,
    insensitive: bool,
    operator: MssqlFilterOperator,
) -> Result<(), AuthError> {
    push_column(query, column, insensitive);
    query.push(match operator {
        MssqlFilterOperator::Eq => " = ",
        MssqlFilterOperator::Ne => " <> ",
        MssqlFilterOperator::Gt => " > ",
        MssqlFilterOperator::Gte => " >= ",
        MssqlFilterOperator::Lt => " < ",
        MssqlFilterOperator::Lte => " <= ",
        _ => unreachable!(),
    });
    let value = normalize_case(
        filter.value.clone(),
        insensitive,
        "insensitive scalar is a string",
    );
    query.bind(model.encode(&filter.field, value)?);
    Ok(())
}

fn normalize_case(value: Value, insensitive: bool, message: &str) -> Value {
    if insensitive {
        Value::String(value.as_str().expect(message).to_lowercase())
    } else {
        value
    }
}

fn push_column(
    query: &mut crate::mssql::statement::MssqlStatement,
    column: &str,
    insensitive: bool,
) {
    if insensitive {
        query.push("lower(").push(column).push(")");
    } else {
        query.push(column);
    }
}
