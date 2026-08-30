use super::{D1ComparisonMode, D1Filter, D1FilterConnector, D1FilterOperator, builder::Query};
use crate::{AuthError, d1::schema::D1Model};
use serde_json::Value;

pub(super) fn push(
    query: &mut Query,
    model: &D1Model<'_>,
    filters: &[D1Filter],
) -> Result<(), AuthError> {
    let and = filters
        .iter()
        .filter(|item| item.connector == D1FilterConnector::And)
        .collect::<Vec<_>>();
    let or = filters
        .iter()
        .filter(|item| item.connector == D1FilterConnector::Or)
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
    query: &mut Query,
    model: &D1Model<'_>,
    filters: &[&D1Filter],
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

fn push_filter(query: &mut Query, model: &D1Model<'_>, filter: &D1Filter) -> Result<(), AuthError> {
    let column = model.quoted_column(&filter.field)?;
    let insensitive = filter.mode == D1ComparisonMode::Insensitive
        && (filter.value.is_string()
            || filter
                .value
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_string)));
    if matches!(
        filter.operator,
        D1FilterOperator::In | D1FilterOperator::NotIn
    ) {
        return push_membership(query, model, filter, column, insensitive);
    }
    if matches!(
        filter.operator,
        D1FilterOperator::Contains | D1FilterOperator::StartsWith | D1FilterOperator::EndsWith
    ) {
        return push_pattern(query, filter, column, insensitive);
    }
    push_scalar(query, model, filter, column, insensitive)
}

fn push_membership(
    query: &mut Query,
    model: &D1Model<'_>,
    filter: &D1Filter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    let values = filter
        .value
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![filter.value.clone()]);
    if values.is_empty() {
        query.push(if filter.operator == D1FilterOperator::In {
            "0 = 1"
        } else {
            "1 = 1"
        });
        return Ok(());
    }
    push_column(query, column, insensitive);
    query.push(if filter.operator == D1FilterOperator::In {
        " in ("
    } else {
        " not in ("
    });
    for (position, value) in values.into_iter().enumerate() {
        if position > 0 {
            query.push(", ");
        }
        let value = if insensitive {
            Value::String(
                value
                    .as_str()
                    .expect("insensitive IN requires strings")
                    .to_lowercase(),
            )
        } else {
            value
        };
        query.bind(model.encode(&filter.field, value)?);
    }
    query.push(")");
    Ok(())
}

fn push_pattern(
    query: &mut Query,
    filter: &D1Filter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    let value = filter.value.as_str().ok_or_else(|| {
        AuthError::InvalidConfiguration("D1 pattern predicates require a string".into())
    })?;
    let pattern = match filter.operator {
        D1FilterOperator::Contains => format!("%{value}%"),
        D1FilterOperator::StartsWith => format!("{value}%"),
        D1FilterOperator::EndsWith => format!("%{value}"),
        _ => unreachable!(),
    };
    push_column(query, column, insensitive);
    query.push(" like ");
    if insensitive {
        query.push("lower(");
    }
    query.bind(super::super::D1Value::Text(pattern));
    if insensitive {
        query.push(")");
    }
    Ok(())
}

fn push_scalar(
    query: &mut Query,
    model: &D1Model<'_>,
    filter: &D1Filter,
    column: &str,
    insensitive: bool,
) -> Result<(), AuthError> {
    match filter.operator {
        D1FilterOperator::Eq | D1FilterOperator::Ne if filter.value.is_null() => {
            query
                .push(column)
                .push(if filter.operator == D1FilterOperator::Eq {
                    " is null"
                } else {
                    " is not null"
                });
        }
        operator @ (D1FilterOperator::Eq
        | D1FilterOperator::Ne
        | D1FilterOperator::Gt
        | D1FilterOperator::Gte
        | D1FilterOperator::Lt
        | D1FilterOperator::Lte) => {
            push_column(query, column, insensitive);
            query.push(match operator {
                D1FilterOperator::Eq => " = ",
                D1FilterOperator::Ne => " <> ",
                D1FilterOperator::Gt => " > ",
                D1FilterOperator::Gte => " >= ",
                D1FilterOperator::Lt => " < ",
                D1FilterOperator::Lte => " <= ",
                _ => unreachable!(),
            });
            let value = if insensitive {
                Value::String(
                    filter
                        .value
                        .as_str()
                        .expect("insensitive scalar requires string")
                        .to_lowercase(),
                )
            } else {
                filter.value.clone()
            };
            query.bind(model.encode(&filter.field, value)?);
        }
        _ => unreachable!("membership and pattern operators are handled first"),
    }
    Ok(())
}

fn push_column(query: &mut Query, column: &str, insensitive: bool) {
    if insensitive {
        query.push("lower(").push(column).push(")");
    } else {
        query.push(column);
    }
}
