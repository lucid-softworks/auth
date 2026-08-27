use super::super::{PostgresModel, PostgresWrite};
use crate::{AuthError, OAuthAccount};
use serde_json::{Map, Value, json};
use sqlx::{Postgres, Transaction, postgres::PgRow};

pub(in crate::postgres) async fn insert_account_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    account: &OAuthAccount,
    id: &crate::store::PreparedDatabaseId,
) -> Result<OAuthAccount, AuthError> {
    let writes = account_writes(model, account, id)?;
    let mut query = super::super::rows::insert_query(model, writes);
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(unique_or_storage)?;
    decode_account(model, &row)
}

pub(in crate::postgres) async fn find_credential_account_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    user_id: &str,
) -> Result<Option<OAuthAccount>, AuthError> {
    let mut query = super::super::rows::select_query(model);
    query
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    super::super::rows::push_model_value(&mut query, model, "userId", json!(user_id))?;
    query
        .push(" AND ")
        .push(model.quoted_column("providerId")?)
        .push(" = ")
        .push_bind("credential".to_owned())
        .push(" FOR UPDATE");
    query
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(super::super::storage_error)?
        .as_ref()
        .map(|row| decode_account(model, row))
        .transpose()
}

pub(in crate::postgres) async fn update_account_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    account: &OAuthAccount,
) -> Result<OAuthAccount, AuthError> {
    let writes = account_update_writes(model, account)?;
    let mut query = super::super::rows::update_query(model, writes);
    query.push(" WHERE \"id\" = ");
    super::super::rows::push_model_value(&mut query, model, "id", json!(account.id))?;
    query.push(" RETURNING ").push(model.all_projection());
    let row = query
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(super::super::storage_error)?
        .ok_or(AuthError::CredentialAccountNotFound)?;
    decode_account(model, &row)
}

pub(in crate::postgres) async fn upsert_account_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    account: &OAuthAccount,
    id: &crate::store::PreparedDatabaseId,
) -> Result<OAuthAccount, AuthError> {
    let update_writes = account_update_writes(model, account)?;
    let writes = account_writes(model, account, id)?;
    let mut query = super::super::rows::insert_query_prefix(model, writes);
    query
        .push(" ON CONFLICT (")
        .push(model.quoted_column("issuer")?)
        .push(", ")
        .push(model.quoted_column("accountId")?)
        .push(") DO UPDATE SET ");
    for (index, write) in update_writes.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        let column = write.quoted_column();
        query.push(column).push(" = EXCLUDED.").push(column);
    }
    query.push(" RETURNING ").push(model.all_projection());
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(unique_or_storage)?;
    decode_account(model, &row)
}

pub(in crate::postgres) fn decode_account(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<OAuthAccount, AuthError> {
    let mut values = model.decode_all(row)?;
    let id = super::super::rows::required_string(&mut values, "id")?;
    let user_id = super::super::rows::required_string(&mut values, "userId")?;
    let issuer = super::super::rows::required_string(&mut values, "issuer")?;
    let account_id = super::super::rows::required_string(&mut values, "accountId")?;
    let provider_id = super::super::rows::required_string(&mut values, "providerId")?;
    let access_token = super::super::rows::optional_string_value(&mut values, "accessToken")?;
    let refresh_token = super::super::rows::optional_string_value(&mut values, "refreshToken")?;
    let id_token = super::super::rows::optional_string_value(&mut values, "idToken")?;
    let access_token_expires_at =
        super::super::rows::optional_date_value(&mut values, "accessTokenExpiresAt")?;
    let refresh_token_expires_at =
        super::super::rows::optional_date_value(&mut values, "refreshTokenExpiresAt")?;
    let scope = super::super::rows::optional_string_value(&mut values, "scope")?;
    let password = super::super::rows::optional_string_value(&mut values, "password")?;
    let created_at = super::super::rows::required_date(&mut values, "createdAt")?;
    let updated_at = super::super::rows::required_date(&mut values, "updatedAt")?;
    Ok(OAuthAccount {
        id,
        user_id,
        issuer,
        account_id,
        provider_id,
        access_token,
        refresh_token,
        id_token,
        access_token_expires_at,
        refresh_token_expires_at,
        scope,
        password,
        additional_fields: values,
        created_at,
        updated_at,
    })
}

pub(super) fn token_writes<'a>(
    model: &'a PostgresModel<'_>,
    account: &OAuthAccount,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let all = account_values(account)?;
    let fields = [
        "providerId",
        "accessToken",
        "refreshToken",
        "idToken",
        "accessTokenExpiresAt",
        "refreshTokenExpiresAt",
        "scope",
        "updatedAt",
    ];
    model.encode_fields(
        fields
            .into_iter()
            .chain(account.additional_fields.keys().map(String::as_str))
            .filter_map(|logical| all.get(logical).cloned().map(|value| (logical, value))),
    )
}

pub(in crate::postgres) fn account_writes<'a>(
    model: &'a PostgresModel<'_>,
    account: &OAuthAccount,
    id: &crate::store::PreparedDatabaseId,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let mut values = account_values(account)?;
    values.remove("id");
    super::super::rows::insert_prepared_id(&mut values, id)?;
    model.encode_fields(
        values
            .iter()
            .map(|(logical, value)| (logical.as_str(), value.clone())),
    )
}

pub(in crate::postgres) fn account_update_writes<'a>(
    model: &'a PostgresModel<'_>,
    account: &OAuthAccount,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let values = account_values(account)?;
    model.encode_fields(
        ["password", "updatedAt"]
            .into_iter()
            .chain(account.additional_fields.keys().map(String::as_str))
            .filter_map(|logical| values.get(logical).cloned().map(|value| (logical, value))),
    )
}

fn account_values(account: &OAuthAccount) -> Result<Map<String, Value>, AuthError> {
    let mut values = Map::new();
    values.insert("id".into(), json!(account.id.to_string()));
    values.insert("userId".into(), json!(account.user_id.to_string()));
    values.insert("issuer".into(), json!(account.issuer));
    values.insert("accountId".into(), json!(account.account_id));
    values.insert("providerId".into(), json!(account.provider_id));
    values.insert(
        "accessToken".into(),
        optional_string(account.access_token.clone()),
    );
    values.insert(
        "refreshToken".into(),
        optional_string(account.refresh_token.clone()),
    );
    values.insert("idToken".into(), optional_string(account.id_token.clone()));
    values.insert(
        "accessTokenExpiresAt".into(),
        super::super::rows::optional_date(account.access_token_expires_at),
    );
    values.insert(
        "refreshTokenExpiresAt".into(),
        super::super::rows::optional_date(account.refresh_token_expires_at),
    );
    values.insert("scope".into(), optional_string(account.scope.clone()));
    values.insert("password".into(), optional_string(account.password.clone()));
    values.insert("createdAt".into(), json!(account.created_at.to_rfc3339()));
    values.insert("updatedAt".into(), json!(account.updated_at.to_rfc3339()));
    for (logical, value) in &account.additional_fields {
        if values.contains_key(logical) {
            return Err(AuthError::InvalidConfiguration(format!(
                "account additional field '{logical}' collides with a canonical Better Auth field"
            )));
        }
        values.insert(logical.clone(), value.clone());
    }
    Ok(values)
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

fn unique_or_storage(error: sqlx::Error) -> AuthError {
    if error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
    {
        AuthError::UserAlreadyExists
    } else {
        super::super::storage_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog,
        ResolvedAdapterSchema,
    };
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    fn physical_schema() -> super::super::super::physical_schema::PostgresPhysicalSchema {
        let mut config = AuthConfig::new([31; 32]).unwrap();
        config.account.model_name = Some("tenant\"accounts".into());
        config.account.fields.user_id = Some("owner id".into());
        config.account.fields.password = Some("secret digest".into());
        config.account.additional_fields.insert(
            "tenantCode".into(),
            AdditionalField::new(AdditionalFieldType::String).field_name("tenant code"),
        );
        config.account.additional_fields.insert(
            "passwordAlias".into(),
            AdditionalField::new(AdditionalFieldType::String).field_name("secret digest"),
        );
        let catalog = Arc::new(AuthSchemaCatalog::build(&config, []).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        super::super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap()
    }

    fn account() -> OAuthAccount {
        let now = Utc::now();
        OAuthAccount {
            id: Uuid::nil().to_string(),
            user_id: Uuid::nil().to_string(),
            issuer: "local:credential".into(),
            account_id: Uuid::nil().to_string(),
            provider_id: "credential".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some("private-value".into()),
            additional_fields: Map::from_iter([
                ("tenantCode".into(), json!("blue")),
                ("passwordAlias".into(), json!("schema-last-value")),
            ]),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn account_insert_uses_canonical_password_and_catalog_identifiers() {
        let physical = physical_schema();
        let model = physical.model("account").unwrap();
        let account = account();
        let writes = account_writes(
            &model,
            &account,
            &super::super::super::rows::explicit_id(account.id.clone()),
        )
        .unwrap();
        let query = super::super::super::rows::insert_query(&model, writes);
        assert!(query.sql().contains("INSERT INTO \"tenant\"\"accounts\""));
        assert!(query.sql().contains("\"owner id\""));
        assert!(query.sql().contains("\"secret digest\""));
        assert!(query.sql().contains("\"tenant code\""));
        assert!(!query.sql().contains("password_hash"));
        assert!(!query.sql().contains("additional_fields"));
        assert!(!query.sql().contains("private-value"));
    }

    #[test]
    fn undeclared_account_fields_are_omitted() {
        let physical = physical_schema();
        let model = physical.model("account").unwrap();
        let mut account = account();
        account
            .additional_fields
            .insert("undeclared".into(), json!(true));
        let writes = account_writes(
            &model,
            &account,
            &super::super::super::rows::explicit_id(account.id.clone()),
        )
        .unwrap();
        assert!(!writes.iter().any(|write| write.logical() == "undeclared"));
    }

    #[test]
    fn account_updates_collapse_physical_aliases_in_schema_order() {
        let physical = physical_schema();
        let model = physical.model("account").unwrap();
        let writes = account_update_writes(&model, &account()).unwrap();
        let password_writes = writes
            .iter()
            .filter(|write| write.column() == "secret digest")
            .collect::<Vec<_>>();
        assert_eq!(password_writes.len(), 1);
        assert_eq!(password_writes[0].logical(), "passwordAlias");
    }
}
