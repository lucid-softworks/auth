use super::{PostgresModel, PostgresStore, PostgresWrite, storage_error};
use crate::{
    AuthError, AuthUser, DatabaseCreate,
    phone_number::{PhoneNumberStore, PhoneNumberWriteOutcome},
};
use async_trait::async_trait;
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};

#[async_trait]
impl PhoneNumberStore for PostgresStore {
    async fn find_user_by_phone_number(
        &self,
        phone_number: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        let model = self.physical_model("user")?;
        require_phone_fields(&model)?;
        let mut query = find_phone_query(&model, phone_number)?;
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(|row| super::rows::decode_user(&model, &row))
            .transpose()
    }

    async fn create_phone_number_user(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError> {
        let (mut user, id) = user.into_parts(self)?;
        let phone_number = require_phone_number(&user)?.to_owned();
        user.email = user.email.to_lowercase();
        let model = self.physical_model("user")?;
        require_phone_fields(&model)?;
        let writes = super::rows::user_writes(&model, &user, &id)?;
        let mut query = insert_user_query(&model, writes);
        match query.build().fetch_one(&self.pool).await {
            Ok(row) => super::rows::decode_user(&model, &row).map(PhoneNumberWriteOutcome::Written),
            Err(error) if is_unique_conflict(&error) => {
                if phone_number_exists(&self.pool, &model, &phone_number).await? {
                    Ok(PhoneNumberWriteOutcome::AlreadyExists)
                } else {
                    Err(AuthError::UserAlreadyExists)
                }
            }
            Err(error) => Err(storage_error(error)),
        }
    }

    async fn update_user_phone_number(
        &self,
        user_id: &str,
        phone_number: Option<String>,
        verified: bool,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError> {
        let model = self.physical_model("user")?;
        require_phone_fields(&model)?;
        let mut query = update_phone_query(&model, user_id, phone_number, verified)?;
        match query.build().fetch_optional(&self.pool).await {
            Ok(Some(row)) => {
                super::rows::decode_user(&model, &row).map(PhoneNumberWriteOutcome::Written)
            }
            Ok(None) => Ok(PhoneNumberWriteOutcome::NotFound),
            Err(error) if is_unique_conflict(&error) => Ok(PhoneNumberWriteOutcome::AlreadyExists),
            Err(error) => Err(storage_error(error)),
        }
    }
}

fn find_phone_query(
    model: &PostgresModel<'_>,
    phone_number: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("phoneNumber")?)
        .push(" = ");
    model
        .encode("phoneNumber", Value::String(phone_number.to_owned()))?
        .push_bind(&mut query);
    query.push(" LIMIT 1");
    Ok(query)
}

fn insert_user_query(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("INSERT INTO ");
    query.push(model.quoted_table()).push(" (");
    for (index, write) in writes.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column());
    }
    query.push(") VALUES (");
    for (index, write) in writes.into_iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        write.push_bind(&mut query);
    }
    query.push(") RETURNING ").push(model.all_projection());
    query
}

fn update_phone_query(
    model: &PostgresModel<'_>,
    user_id: &str,
    phone_number: Option<String>,
    verified: bool,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let phone_number = model.encode(
        "phoneNumber",
        phone_number.map_or(Value::Null, Value::String),
    )?;
    let verified = model.encode("phoneNumberVerified", json!(verified))?;
    let updated_at = model.encode("updatedAt", json!(chrono::Utc::now().to_rfc3339()))?;
    let user_id = model.encode("id", json!(user_id))?;
    let mut query = QueryBuilder::new("UPDATE ");
    query
        .push(model.quoted_table())
        .push(" SET ")
        .push(model.quoted_column("phoneNumber")?)
        .push(" = ");
    phone_number.push_bind(&mut query);
    query
        .push(", ")
        .push(model.quoted_column("phoneNumberVerified")?)
        .push(" = ");
    verified.push_bind(&mut query);
    query
        .push(", ")
        .push(model.quoted_column("updatedAt")?)
        .push(" = ");
    updated_at.push_bind(&mut query);
    query.push(" WHERE \"id\" = ");
    user_id.push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    Ok(query)
}

async fn phone_number_exists(
    pool: &sqlx::PgPool,
    model: &PostgresModel<'_>,
    phone_number: &str,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("phoneNumber")?)
        .push(" = ");
    model
        .encode("phoneNumber", Value::String(phone_number.to_owned()))?
        .push_bind(&mut query);
    query.push(")");
    query
        .build_query_scalar::<bool>()
        .fetch_one(pool)
        .await
        .map_err(storage_error)
}

fn require_phone_fields(model: &PostgresModel<'_>) -> Result<(), AuthError> {
    model.quoted_column("phoneNumber")?;
    model.quoted_column("phoneNumberVerified")?;
    Ok(())
}

fn require_phone_number(user: &AuthUser) -> Result<&str, AuthError> {
    user.additional_fields
        .get("phoneNumber")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::Storage("phone-number user requires a phone number".into()))
}

fn is_unique_conflict(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog,
        PluginSchemaTable, ResolvedAdapterSchema,
    };
    use std::sync::Arc;

    fn physical_schema() -> super::super::physical_schema::PostgresPhysicalSchema {
        let mut config = AuthConfig::new([19; 32]).unwrap();
        config.user.model_name = Some("tenant\"users".into());
        config.user.fields.email = Some("mail address".into());
        let table = PluginSchemaTable::new("user")
            .field(
                "phoneNumber",
                AdditionalField::new(AdditionalFieldType::String)
                    .optional()
                    .unique(true)
                    .field_name("phone\"number"),
            )
            .field(
                "phoneNumberVerified",
                AdditionalField::new(AdditionalFieldType::Boolean)
                    .optional()
                    .field_name("phone verified"),
            );
        let catalog = Arc::new(AuthSchemaCatalog::build(&config, [table]).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap()
    }

    #[test]
    fn phone_queries_use_catalog_remaps_and_bound_values() {
        let physical = physical_schema();
        let model = physical.model("user").unwrap();
        let find = find_phone_query(&model, "+440000000000").unwrap();
        assert!(find.sql().contains("FROM \"tenant\"\"users\""));
        assert!(find.sql().contains("\"phone\"\"number\" = $1"));
        assert!(
            find.sql()
                .contains("\"phone\"\"number\" AS \"phoneNumber\"")
        );
        assert!(find.sql().contains("\"mail address\" AS \"email\""));
        assert!(!find.sql().contains("+440000000000"));

        let update = update_phone_query(
            &model,
            &uuid::Uuid::nil().to_string(),
            Some("+440000000000".into()),
            true,
        )
        .unwrap();
        assert!(update.sql().contains("UPDATE \"tenant\"\"users\" SET"));
        assert!(update.sql().contains("\"phone verified\" = $2"));
        assert_eq!(update.sql().matches('$').count(), 4);
        assert!(!update.sql().contains("+440000000000"));
    }

    #[test]
    fn absent_phone_numbers_bind_as_sql_null() {
        let physical = physical_schema();
        let model = physical.model("user").unwrap();
        assert!(matches!(
            model.encode("phoneNumber", Value::Null).unwrap(),
            super::super::PostgresValue::Text(None)
        ));
        assert!(matches!(
            model.encode("phoneNumberVerified", json!(false)).unwrap(),
            super::super::PostgresValue::Boolean(Some(false))
        ));
    }
}
