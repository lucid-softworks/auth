use super::*;

impl AuthService {
    pub(super) async fn dash_adapter_find_many(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&crate::DashAdapterSort>,
        join: Option<&std::collections::BTreeMap<String, bool>>,
    ) -> Result<Vec<Value>, AuthError> {
        if let Some(mut values) = self
            .dash_adapter_store_records(model, where_clause, limit, offset, sort)
            .await?
        {
            self.dash_attach_joins(model, &mut values, join).await?;
            return Ok(values);
        }
        self.dash_adapter_find_builtin(model, where_clause, limit, offset, sort, join)
            .await
    }

    async fn dash_adapter_store_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&crate::DashAdapterSort>,
    ) -> Result<Option<Vec<Value>>, AuthError> {
        Ok(self
            .store
            .dash_find_records(model, where_clause, limit, offset, sort, &[])
            .await?
            .map(|records| records.into_iter().map(Value::Object).collect()))
    }

    async fn dash_adapter_find_builtin(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&crate::DashAdapterSort>,
        join: Option<&std::collections::BTreeMap<String, bool>>,
    ) -> Result<Vec<Value>, AuthError> {
        let mut values = match model {
            "user" => {
                self.dash_adapter_find_users(where_clause, limit, offset, sort, join)
                    .await?
            }
            "account" => {
                let user_id = equality_string(where_clause, "userId")?;
                self.store
                    .list_user_accounts(user_id)
                    .await?
                    .into_iter()
                    .map(|account| serde_json::to_value(account).expect("account value"))
                    .filter(|value| dash_matches(value, where_clause))
                    .collect()
            }
            "session" => {
                let user_id = equality_string(where_clause, "userId")?;
                self.store
                    .list_sessions(user_id)
                    .await?
                    .into_iter()
                    .map(|session| serde_json::to_value(session).expect("session value"))
                    .filter(|value| dash_matches(value, where_clause))
                    .collect()
            }
            _ => {
                return Err(AuthError::Storage(format!(
                    "the configured adapter does not expose model '{model}'"
                )));
            }
        };
        if model != "user" {
            sort_values(&mut values, sort);
            values = values
                .into_iter()
                .skip(offset)
                .take(limit.unwrap_or(usize::MAX))
                .collect();
        }
        Ok(values)
    }

    async fn dash_adapter_find_users(
        &self,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&crate::DashAdapterSort>,
        join: Option<&std::collections::BTreeMap<String, bool>>,
    ) -> Result<Vec<Value>, AuthError> {
        let conditions = where_clause
            .iter()
            .map(dash_adapter_condition)
            .collect::<Result<Vec<_>, _>>()?;
        let users = self
            .store
            .list_users(&AdminListUsersQuery {
                limit: limit.unwrap_or(usize::MAX),
                offset,
                sort_by: sort.map(|sort| sort.field.clone()),
                sort_direction: match sort.map(|sort| sort.direction) {
                    Some(DashSortDirection::Desc) => AdminSortDirection::Desc,
                    _ => AdminSortDirection::Asc,
                },
                conditions,
            })
            .await?;
        let mut output = Vec::with_capacity(users.len());
        for user in users {
            let mut value = serde_json::to_value(&user)
                .map_err(|error| AuthError::Storage(error.to_string()))?;
            if join.is_some_and(|join| join.get("account") == Some(&true)) {
                value.as_object_mut().expect("user object").insert(
                    "account".into(),
                    serde_json::to_value(self.store.list_user_accounts(&user.id).await?)
                        .map_err(|error| AuthError::Storage(error.to_string()))?,
                );
            }
            if join.is_some_and(|join| join.get("session") == Some(&true)) {
                value.as_object_mut().expect("user object").insert(
                    "session".into(),
                    serde_json::to_value(self.store.list_sessions(&user.id).await?)
                        .map_err(|error| AuthError::Storage(error.to_string()))?,
                );
            }
            output.push(value);
        }
        Ok(output)
    }

    async fn dash_attach_joins(
        &self,
        model: &str,
        records: &mut [Value],
        join: Option<&std::collections::BTreeMap<String, bool>>,
    ) -> Result<(), AuthError> {
        let Some(join) = join else {
            return Ok(());
        };
        for (joined_model, enabled) in join {
            if !enabled {
                continue;
            }
            for record in records.iter_mut() {
                self.dash_attach_join(model, record, joined_model).await?;
            }
        }
        Ok(())
    }

    async fn dash_attach_join(
        &self,
        model: &str,
        record: &mut Value,
        joined_model: &str,
    ) -> Result<(), AuthError> {
        let schema = self.database_schema();
        let base = schema
            .table(model)
            .ok_or_else(|| unsupported_model(model))?;
        let joined = schema
            .table(joined_model)
            .ok_or_else(|| unsupported_model(joined_model))?;
        let parent_relation = base
            .fields
            .iter()
            .filter_map(|(field, value)| {
                value
                    .references
                    .as_ref()
                    .map(|reference| (field, reference))
            })
            .find(|(_, reference)| reference.model == joined_model)
            .map(|(field, reference)| (field.clone(), reference.field.clone()));
        if let Some((source_field, target_field)) = parent_relation {
            return self
                .dash_attach_parent(record, joined_model, &source_field, &target_field)
                .await;
        }
        let child_relation = joined
            .fields
            .iter()
            .filter_map(|(field, value)| {
                value
                    .references
                    .as_ref()
                    .map(|reference| (field, reference))
            })
            .find(|(_, reference)| reference.model == model)
            .map(|(field, reference)| (field.clone(), reference.field.clone()));
        if let Some((target_field, source_field)) = child_relation {
            self.dash_attach_children(record, joined_model, &source_field, &target_field)
                .await?;
        }
        Ok(())
    }

    async fn dash_attach_parent(
        &self,
        record: &mut Value,
        joined_model: &str,
        source_field: &str,
        target_field: &str,
    ) -> Result<(), AuthError> {
        let value = record.get(source_field).cloned().unwrap_or(Value::Null);
        let related = self
            .store
            .dash_find_records(
                joined_model,
                &[DashAdapterWhere {
                    field: target_field.into(),
                    value,
                    operator: crate::DashAdapterOperator::Eq,
                    connector: None,
                }],
                Some(1),
                0,
                None,
                &[],
            )
            .await?
            .ok_or_else(|| unsupported_model(joined_model))?
            .into_iter()
            .next()
            .map(Value::Object)
            .unwrap_or(Value::Null);
        record
            .as_object_mut()
            .expect("adapter record is an object")
            .insert(joined_model.into(), related);
        Ok(())
    }

    async fn dash_attach_children(
        &self,
        record: &mut Value,
        joined_model: &str,
        source_field: &str,
        target_field: &str,
    ) -> Result<(), AuthError> {
        let value = record.get(source_field).cloned().unwrap_or(Value::Null);
        let related = self
            .store
            .dash_find_records(
                joined_model,
                &[DashAdapterWhere {
                    field: target_field.into(),
                    value,
                    operator: crate::DashAdapterOperator::Eq,
                    connector: None,
                }],
                None,
                0,
                None,
                &[],
            )
            .await?
            .ok_or_else(|| unsupported_model(joined_model))?
            .into_iter()
            .map(Value::Object)
            .collect();
        record
            .as_object_mut()
            .expect("adapter record is an object")
            .insert(joined_model.into(), Value::Array(related));
        Ok(())
    }
}

fn sort_values(values: &mut [Value], sort: Option<&crate::DashAdapterSort>) {
    let Some(sort) = sort else {
        return;
    };
    values.sort_by(|left, right| {
        let ordering = left
            .get(&sort.field)
            .zip(right.get(&sort.field))
            .and_then(|(left, right)| compare_values(left, right))
            .unwrap_or(std::cmp::Ordering::Equal);
        match sort.direction {
            DashSortDirection::Asc => ordering,
            DashSortDirection::Desc => ordering.reverse(),
        }
    });
}
