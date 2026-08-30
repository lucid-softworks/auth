use super::MemoryTransaction;
use crate::{
    AuthError, DashAdapterConnector, DashAdapterOperator, DashAdapterSort, DashAdapterWhere,
    DashSortDirection,
};
use serde_json::{Map, Number, Value};

pub(super) async fn find(
    transaction: &MemoryTransaction,
    model: &str,
    where_clause: &[DashAdapterWhere],
    limit: Option<usize>,
    offset: usize,
    sort: Option<&DashAdapterSort>,
    select: &[String],
) -> Result<Vec<Map<String, Value>>, AuthError> {
    transaction.ensure_active()?;
    let state = transaction.store.state.read().await;
    let mut records = state
        .logical_records
        .get(model)
        .into_iter()
        .flatten()
        .filter(|record| matches_where(record, where_clause))
        .cloned()
        .collect::<Vec<_>>();
    if let Some(sort) = sort {
        records.sort_by(|left, right| {
            let ordering = compare_values(
                left.get(&sort.field).unwrap_or(&Value::Null),
                right.get(&sort.field).unwrap_or(&Value::Null),
            )
            .unwrap_or(std::cmp::Ordering::Equal);
            match sort.direction {
                DashSortDirection::Asc => ordering,
                DashSortDirection::Desc => ordering.reverse(),
            }
        });
    }
    Ok(records
        .into_iter()
        .skip(offset)
        .take(limit.unwrap_or(usize::MAX))
        .map(|record| select_fields(record, select))
        .collect())
}

pub(super) async fn create(
    transaction: &MemoryTransaction,
    model: &str,
    data: Map<String, Value>,
) -> Result<Map<String, Value>, AuthError> {
    transaction.ensure_active()?;
    let mut state = transaction.store.state.write().await;
    let records = state.logical_records.entry(model.into()).or_default();
    if let Some(id) = data.get("id")
        && records.iter().any(|record| record.get("id") == Some(id))
    {
        return Err(AuthError::Storage(format!(
            "logical model '{model}' id already exists"
        )));
    }
    records.push(data.clone());
    Ok(data)
}

pub(super) async fn update(
    transaction: &MemoryTransaction,
    model: &str,
    where_clause: &[DashAdapterWhere],
    update: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    transaction.ensure_active()?;
    if where_clause.is_empty() {
        return Ok(None);
    }
    let mut state = transaction.store.state.write().await;
    let Some(record) = state.logical_records.get_mut(model).and_then(|records| {
        records
            .iter_mut()
            .find(|record| matches_where(record, where_clause))
    }) else {
        return Ok(None);
    };
    record.extend(update);
    Ok(Some(record.clone()))
}

pub(super) async fn delete(
    transaction: &MemoryTransaction,
    model: &str,
    where_clause: &[DashAdapterWhere],
) -> Result<u64, AuthError> {
    transaction.ensure_active()?;
    let mut state = transaction.store.state.write().await;
    let Some(records) = state.logical_records.get_mut(model) else {
        return Ok(0);
    };
    let before = records.len();
    records.retain(|record| !matches_where(record, where_clause));
    Ok((before - records.len()) as u64)
}

pub(super) async fn count(
    transaction: &MemoryTransaction,
    model: &str,
    where_clause: &[DashAdapterWhere],
) -> Result<u64, AuthError> {
    transaction.ensure_active()?;
    let state = transaction.store.state.read().await;
    Ok(state
        .logical_records
        .get(model)
        .into_iter()
        .flatten()
        .filter(|record| matches_where(record, where_clause))
        .count() as u64)
}

pub(super) async fn increment(
    transaction: &MemoryTransaction,
    model: &str,
    where_clause: &[DashAdapterWhere],
    increments: Map<String, Value>,
    set: Map<String, Value>,
) -> Result<Option<Map<String, Value>>, AuthError> {
    transaction.ensure_active()?;
    if where_clause.is_empty() {
        return Ok(None);
    }
    let mut state = transaction.store.state.write().await;
    let Some(record) = state.logical_records.get_mut(model).and_then(|records| {
        records
            .iter_mut()
            .find(|record| matches_where(record, where_clause))
    }) else {
        return Ok(None);
    };
    for (field, increment) in increments {
        let current = record.get(&field).unwrap_or(&Value::Null);
        record.insert(field.clone(), add_numbers(current, &increment, &field)?);
    }
    record.extend(set);
    Ok(Some(record.clone()))
}

fn select_fields(mut record: Map<String, Value>, select: &[String]) -> Map<String, Value> {
    if !select.is_empty() {
        record.retain(|field, _| select.iter().any(|selected| selected == field));
    }
    record
}

fn matches_where(record: &Map<String, Value>, conditions: &[DashAdapterWhere]) -> bool {
    let and_matches = conditions
        .iter()
        .filter(|condition| {
            condition.connector.unwrap_or(DashAdapterConnector::And) == DashAdapterConnector::And
        })
        .all(|condition| matches_condition(record, condition));
    let mut or = conditions
        .iter()
        .filter(|condition| condition.connector == Some(DashAdapterConnector::Or))
        .peekable();
    and_matches && (or.peek().is_none() || or.any(|condition| matches_condition(record, condition)))
}

fn matches_condition(record: &Map<String, Value>, condition: &DashAdapterWhere) -> bool {
    let candidate = record.get(&condition.field).unwrap_or(&Value::Null);
    match condition.operator {
        DashAdapterOperator::Eq => candidate == &condition.value,
        DashAdapterOperator::Ne => candidate != &condition.value,
        DashAdapterOperator::In => condition
            .value
            .as_array()
            .is_some_and(|values| values.contains(candidate)),
        DashAdapterOperator::Contains => string_pair(candidate, &condition.value)
            .is_some_and(|(candidate, expected)| candidate.contains(expected)),
        DashAdapterOperator::StartsWith => string_pair(candidate, &condition.value)
            .is_some_and(|(candidate, expected)| candidate.starts_with(expected)),
        DashAdapterOperator::EndsWith => string_pair(candidate, &condition.value)
            .is_some_and(|(candidate, expected)| candidate.ends_with(expected)),
        DashAdapterOperator::Gt
        | DashAdapterOperator::Gte
        | DashAdapterOperator::Lt
        | DashAdapterOperator::Lte => compare_values(candidate, &condition.value).is_some_and(
            |ordering| match condition.operator {
                DashAdapterOperator::Gt => ordering.is_gt(),
                DashAdapterOperator::Gte => !ordering.is_lt(),
                DashAdapterOperator::Lt => ordering.is_lt(),
                DashAdapterOperator::Lte => !ordering.is_gt(),
                _ => false,
            },
        ),
    }
}

fn string_pair<'a>(left: &'a Value, right: &'a Value) -> Option<(&'a str, &'a str)> {
    left.as_str().zip(right.as_str())
}

fn compare_values(left: &Value, right: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
        return left.partial_cmp(&right);
    }
    left.as_str()?.partial_cmp(right.as_str()?)
}

fn add_numbers(current: &Value, increment: &Value, field: &str) -> Result<Value, AuthError> {
    if let (Some(current), Some(increment)) = (current.as_i64(), increment.as_i64()) {
        return current
            .checked_add(increment)
            .map(Number::from)
            .map(Value::Number)
            .ok_or_else(|| AuthError::Storage(format!("logical field '{field}' overflowed")));
    }
    current
        .as_f64()
        .zip(increment.as_f64())
        .and_then(|(current, increment)| Number::from_f64(current + increment))
        .map(Value::Number)
        .ok_or_else(|| {
            AuthError::InvalidConfiguration(format!(
                "logical field '{field}' is not incrementable"
            ))
        })
}

#[cfg(test)]
mod tests {
    use crate::{
        AuthError, DashAdapterWhere, MemoryStore, run_database_transaction,
    };
    use serde_json::json;

    #[tokio::test]
    async fn logical_plugin_rows_commit_with_revision_fences_and_projection() {
        let store = MemoryStore::default();
        let stored = run_database_transaction(&store, |transaction| {
            Box::pin(async move {
                transaction
                    .create_record(
                        "scimSubject",
                        object(json!({
                            "id": "subject-1",
                            "userId": "user-1",
                            "revision": 0,
                        })),
                    )
                    .await?;
                assert_eq!(
                    transaction
                        .count_records("scimSubject", &[equal("userId", json!("user-1"))])
                        .await?,
                    1
                );
                transaction
                    .increment_record(
                        "scimSubject",
                        &[equal("revision", json!(0))],
                        object(json!({ "revision": 1 })),
                        object(json!({ "active": true })),
                    )
                    .await?
                    .ok_or(AuthError::NotFound)
            })
        })
        .await
        .unwrap();
        assert_eq!(stored["revision"], 1);
        assert_eq!(stored["active"], true);

        let visible = run_database_transaction(&store, |transaction| {
            Box::pin(async move {
                transaction
                    .find_records(
                        "scimSubject",
                        &[],
                        Some(1),
                        0,
                        None,
                        &["id".into(), "revision".into()],
                    )
                    .await
            })
        })
        .await
        .unwrap();
        assert_eq!(visible, [object(json!({ "id": "subject-1", "revision": 1 }))]);
    }

    #[tokio::test]
    async fn logical_plugin_rows_roll_back_with_the_transaction() {
        let store = MemoryStore::default();
        run_database_transaction(&store, |transaction| {
            Box::pin(async move {
                transaction
                    .create_record("scimSubject", object(json!({ "id": "subject-1" })))
                    .await
            })
        })
        .await
        .unwrap();
        let error = run_database_transaction::<(), _>(&store, |transaction| {
            Box::pin(async move {
                transaction.delete_records("scimSubject", &[]).await?;
                Err(AuthError::Storage("rollback".into()))
            })
        })
        .await
        .unwrap_err();
        assert!(matches!(error, AuthError::Storage(message) if message == "rollback"));
        let remaining = run_database_transaction(&store, |transaction| {
            Box::pin(async move { transaction.count_records("scimSubject", &[]).await })
        })
        .await
        .unwrap();
        assert_eq!(remaining, 1);
    }

    fn equal(field: &str, value: serde_json::Value) -> DashAdapterWhere {
        DashAdapterWhere {
            field: field.into(),
            value,
            operator: Default::default(),
            connector: None,
        }
    }

    fn object(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().cloned().unwrap()
    }
}
