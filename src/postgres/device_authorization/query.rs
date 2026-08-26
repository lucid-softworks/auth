use super::{super::PostgresModel, codec};
use crate::{AuthError, DeviceCode};
use serde_json::Value;
use sqlx::{Postgres, QueryBuilder};

pub(super) fn insert(
    model: &PostgresModel<'_>,
    code: &DeviceCode,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = codec::writes(model, code)?;
    let mut query = super::super::rows::insert_query_prefix(model, writes);
    query.push(" RETURNING ").push(model.all_projection());
    Ok(query)
}

pub(super) fn find_by(
    model: &PostgresModel<'_>,
    field: &str,
    value: Value,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = select(model);
    query
        .push(" WHERE ")
        .push(model.quoted_column(field)?)
        .push(" = ");
    model.encode(field, value)?.push_bind(&mut query);
    Ok(query)
}

pub(super) fn update_field(
    model: &PostgresModel<'_>,
    id: uuid::Uuid,
    field: &str,
    value: Value,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = model.encode_fields([(field, value)])?;
    let mut query = super::super::rows::update_query(model, writes);
    query
        .push(" WHERE \"id\" = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(model.all_projection());
    Ok(query)
}

pub(super) fn bind_pending_user(
    model: &PostgresModel<'_>,
    id: uuid::Uuid,
    user_id: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = model.encode_fields([("userId", Value::String(user_id.to_owned()))])?;
    let mut query = super::super::rows::update_query(model, writes);
    query
        .push(" WHERE \"id\" = ")
        .push_bind(id)
        .push(" AND ")
        .push(model.quoted_column("status")?)
        .push(" = ");
    model
        .encode("status", Value::String("pending".into()))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" IS NULL RETURNING ")
        .push(model.all_projection());
    Ok(query)
}

pub(super) fn delete(model: &PostgresModel<'_>, id: uuid::Uuid) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ")
        .push_bind(id)
        .push(" RETURNING ")
        .push(model.all_projection());
    query
}

pub(super) fn consume(
    model: &PostgresModel<'_>,
    id: uuid::Uuid,
    owner_field: &str,
    owner_value: String,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ")
        .push_bind(id)
        .push(" AND ")
        .push(model.quoted_column(owner_field)?)
        .push(" = ");
    model
        .encode(owner_field, Value::String(owner_value))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("status")?)
        .push(" = ");
    model
        .encode("status", Value::String("approved".into()))?
        .push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    Ok(query)
}

fn select(model: &PostgresModel<'_>) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
    query
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, AuthSchemaCatalog, DeviceAuthorizationModelSchema, DeviceAuthorizationSchema,
        DeviceCodeStatus,
        postgres::{PostgresAdapterConfig, PostgresStore},
    };
    use chrono::{Duration, Utc};
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use std::{collections::BTreeMap, sync::Arc};

    fn store(with_device_code: bool) -> PostgresStore {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/device_schema_test")
            .unwrap();
        let store = PostgresStore::new(pool, PostgresAdapterConfig { use_plural: true });
        let config = AuthConfig::new([45; 32]).unwrap();
        let tables = with_device_code
            .then(|| {
                crate::device_authorization::schema::catalog(
                    &DeviceAuthorizationSchema {
                        device_code: DeviceAuthorizationModelSchema {
                            model_name: Some("device record".into()),
                            fields: BTreeMap::from([
                                ("deviceCode".into(), "device\"secret".into()),
                                ("userCode".into(), "user code".into()),
                                ("status".into(), "select".into()),
                            ]),
                        },
                    },
                    true,
                )
            })
            .into_iter()
            .collect::<Vec<_>>();
        store
            .bind_catalog(Arc::new(AuthSchemaCatalog::build(&config, tables).unwrap()))
            .unwrap();
        store
    }

    fn code() -> DeviceCode {
        DeviceCode {
            id: uuid::Uuid::new_v4(),
            device_code: "private-device-code".into(),
            user_code: "PRIVATE".into(),
            user_id: None,
            expires_at: Utc::now() + Duration::minutes(1),
            status: DeviceCodeStatus::Approved,
            last_polled_at: None,
            polling_interval: Some(5_000.0),
            client_id: Some("client".into()),
            scope: None,
            resources: Some(vec!["https://resource.example".into()]),
            oauth_client_id: Some("oauth-client".into()),
        }
    }

    #[tokio::test]
    async fn every_operation_uses_the_bound_plural_model_and_quoted_fields() {
        let store = store(true);
        let model = store.physical_model("deviceCode").unwrap();
        let code = code();
        let sql = [
            insert(&model, &code).unwrap().sql().to_owned(),
            find_by(
                &model,
                "deviceCode",
                Value::String(code.device_code.clone()),
            )
            .unwrap()
            .sql()
            .to_owned(),
            bind_pending_user(&model, code.id, &uuid::Uuid::new_v4().to_string())
                .unwrap()
                .sql()
                .to_owned(),
            update_field(&model, code.id, "status", json!("denied"))
                .unwrap()
                .sql()
                .to_owned(),
            delete(&model, code.id).sql().to_owned(),
            consume(&model, code.id, "oauthClientId", "oauth-client".into())
                .unwrap()
                .sql()
                .to_owned(),
        ]
        .join("\n");
        assert!(sql.contains("\"device records\""));
        assert!(sql.contains("\"device\"\"secret\""));
        assert!(sql.contains("\"user code\""));
        assert!(sql.contains("\"select\""));
        assert!(!sql.contains("lucid_auth_device_codes"));
        assert!(!sql.contains("private-device-code"));
        assert!(!sql.contains("oauth-client"));
    }

    #[tokio::test]
    async fn missing_plugin_model_fails_without_a_default_table_fallback() {
        let store = store(false);
        assert!(store.physical_model("deviceCode").is_err());
    }
}
