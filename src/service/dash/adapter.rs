use super::*;

impl AuthService {
    pub(crate) async fn dash_execute_adapter(
        &self,
        action: DashAdapterAction,
    ) -> Result<Value, AuthError> {
        match action {
            DashAdapterAction::FindOne {
                model,
                where_clause,
                select,
                join,
            } => {
                let mut records = self
                    .dash_adapter_find_many(
                        &model,
                        where_clause.as_deref().unwrap_or(&[]),
                        Some(1),
                        0,
                        join.as_ref(),
                    )
                    .await?;
                let result = records.pop().map(|value| project(value, select.as_deref()));
                Ok(json!({"result": result}))
            }
            DashAdapterAction::FindMany {
                model,
                where_clause,
                limit,
                offset,
                sort_by: _,
                join,
            } => {
                let records = self
                    .dash_adapter_find_many(
                        &model,
                        where_clause.as_deref().unwrap_or(&[]),
                        limit.map(js_index),
                        offset.map(js_index).unwrap_or(0),
                        join.as_ref(),
                    )
                    .await?;
                Ok(json!({"result": records}))
            }
            DashAdapterAction::Create { model, data } if model == "user" => {
                Ok(json!({"result": self.dash_create_user_body(data).await?}))
            }
            DashAdapterAction::Update {
                model,
                where_clause,
                update,
            } if model == "user" => {
                let user_id = equality_string(&where_clause, "id")?;
                Ok(json!({"result": self.dash_update_user_body(user_id, update).await?}))
            }
            DashAdapterAction::Count {
                model,
                where_clause,
            } => {
                let count = self
                    .dash_adapter_find_many(
                        &model,
                        where_clause.as_deref().unwrap_or(&[]),
                        None,
                        0,
                        None,
                    )
                    .await?
                    .len();
                Ok(json!({"count": count}))
            }
            _ => Err(AuthError::Storage(
                "the configured adapter does not expose this model mutation".into(),
            )),
        }
    }

    async fn dash_adapter_find_many(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        join: Option<&std::collections::BTreeMap<String, bool>>,
    ) -> Result<Vec<Value>, AuthError> {
        let mut values = match model {
            "user" => {
                let conditions = where_clause
                    .iter()
                    .map(dash_adapter_condition)
                    .collect::<Result<Vec<_>, _>>()?;
                let users = self
                    .store
                    .list_users(&AdminListUsersQuery {
                        limit: limit.unwrap_or(usize::MAX),
                        offset,
                        conditions,
                        ..AdminListUsersQuery::default()
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
                output
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
            values = values
                .into_iter()
                .skip(offset)
                .take(limit.unwrap_or(usize::MAX))
                .collect();
        }
        Ok(values)
    }
}
