use super::*;

mod query;

fn unsupported_model(model: &str) -> AuthError {
    AuthError::Storage(format!(
        "the configured adapter does not expose model '{model}'"
    ))
}

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
                self.dash_adapter_find_one_action(model, where_clause, select, join)
                    .await
            }
            DashAdapterAction::FindMany {
                model,
                where_clause,
                limit,
                offset,
                sort_by,
                join,
            } => {
                self.dash_adapter_find_many_action(
                    model,
                    where_clause,
                    limit,
                    offset,
                    sort_by,
                    join,
                )
                .await
            }
            DashAdapterAction::Create { model, data } if model == "user" => {
                Ok(json!({"result": self.dash_create_user_body(data).await?}))
            }
            DashAdapterAction::Create { model, data } => {
                self.dash_adapter_create_action(model, data).await
            }
            DashAdapterAction::Update {
                model,
                where_clause,
                update,
            } if model == "user" => {
                let user_id = equality_string(&where_clause, "id")?;
                Ok(json!({"result": self.dash_update_user_body(user_id, update).await?}))
            }
            DashAdapterAction::Update {
                model,
                where_clause,
                update,
            } => {
                self.dash_adapter_update_action(model, where_clause, update)
                    .await
            }
            DashAdapterAction::Count {
                model,
                where_clause,
            } => self.dash_adapter_count_action(model, where_clause).await,
        }
    }

    async fn dash_adapter_find_one_action(
        &self,
        model: String,
        where_clause: Option<Vec<DashAdapterWhere>>,
        select: Option<Vec<String>>,
        join: Option<std::collections::BTreeMap<String, bool>>,
    ) -> Result<Value, AuthError> {
        let mut records = self
            .dash_adapter_find_many(
                &model,
                where_clause.as_deref().unwrap_or(&[]),
                Some(1),
                0,
                None,
                join.as_ref(),
            )
            .await?;
        let result = records.pop().map(|value| project(value, select.as_deref()));
        Ok(json!({"result": result}))
    }

    async fn dash_adapter_find_many_action(
        &self,
        model: String,
        where_clause: Option<Vec<DashAdapterWhere>>,
        limit: Option<f64>,
        offset: Option<f64>,
        sort: Option<crate::DashAdapterSort>,
        join: Option<std::collections::BTreeMap<String, bool>>,
    ) -> Result<Value, AuthError> {
        let records = self
            .dash_adapter_find_many(
                &model,
                where_clause.as_deref().unwrap_or(&[]),
                limit.map(js_index),
                offset.map(js_index).unwrap_or(0),
                sort.as_ref(),
                join.as_ref(),
            )
            .await?;
        Ok(json!({"result": records}))
    }

    async fn dash_adapter_create_action(
        &self,
        model: String,
        data: Map<String, Value>,
    ) -> Result<Value, AuthError> {
        let result = self
            .store
            .dash_create_record(&model, data)
            .await?
            .ok_or_else(|| unsupported_model(&model))?;
        Ok(json!({"result": result}))
    }

    async fn dash_adapter_update_action(
        &self,
        model: String,
        where_clause: Vec<DashAdapterWhere>,
        update: Map<String, Value>,
    ) -> Result<Value, AuthError> {
        let result = self
            .store
            .dash_update_record(&model, &where_clause, update)
            .await?
            .ok_or_else(|| unsupported_model(&model))?;
        Ok(json!({"result": result}))
    }

    async fn dash_adapter_count_action(
        &self,
        model: String,
        where_clause: Option<Vec<DashAdapterWhere>>,
    ) -> Result<Value, AuthError> {
        let where_clause = where_clause.as_deref().unwrap_or(&[]);
        if let Some(count) = self.store.dash_count_records(&model, where_clause).await? {
            return Ok(json!({"count": count}));
        }
        let count = self
            .dash_adapter_find_many(&model, where_clause, None, 0, None, None)
            .await?
            .len();
        Ok(json!({"count": count}))
    }
}
