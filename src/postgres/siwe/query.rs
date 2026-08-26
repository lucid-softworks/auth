use super::super::{PostgresModel, storage_error};
use crate::{AuthError, WalletAddress, WalletAddressOwner};
use serde_json::{Map, Value, json};
use sqlx::{Postgres, QueryBuilder, Transaction, postgres::PgRow};

pub(super) async fn find_wallet_pool(
    pool: &sqlx::PgPool,
    model: &PostgresModel<'_>,
    address: &str,
    chain_id: Option<f64>,
) -> Result<Option<WalletAddress>, AuthError> {
    let mut query = wallet_query(model, address, chain_id)?;
    query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(storage_error)?
        .map(|row| decode_wallet(model, &row))
        .transpose()
}

pub(super) async fn find_owner_tx(
    transaction: &mut Transaction<'_, Postgres>,
    wallet_model: &PostgresModel<'_>,
    user_model: &PostgresModel<'_>,
    address: &str,
    chain_id: Option<f64>,
) -> Result<Option<WalletAddressOwner>, AuthError> {
    let mut query = wallet_query(wallet_model, address, chain_id)?;
    let wallet = query
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?
        .map(|row| decode_wallet(wallet_model, &row))
        .transpose()?;
    let Some(wallet) = wallet else {
        return Ok(None);
    };
    let user = super::super::user::load_by_id_transaction(transaction, user_model, &wallet.user_id)
        .await?
        .ok_or_else(|| AuthError::Storage("SIWE wallet owner is missing".into()))?;
    Ok(Some(WalletAddressOwner { wallet, user }))
}

fn wallet_query(
    model: &PostgresModel<'_>,
    address: &str,
    chain_id: Option<f64>,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE lower(")
        .push(model.quoted_column("address")?)
        .push(") = lower(");
    model
        .encode("address", Value::String(address.to_owned()))?
        .push_bind(&mut query);
    query.push(")");
    if let Some(chain_id) = chain_id {
        query
            .push(" AND ")
            .push(model.quoted_column("chainId")?)
            .push(" = ");
        model
            .encode("chainId", chain_id_value(chain_id)?)?
            .push_bind(&mut query);
    } else {
        query
            .push(" ORDER BY ")
            .push(model.quoted_column("createdAt")?)
            .push(" ASC, \"id\" ASC");
    }
    query.push(" LIMIT 1");
    Ok(query)
}

fn decode_wallet(model: &PostgresModel<'_>, row: &PgRow) -> Result<WalletAddress, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(WalletAddress {
        id: required_uuid(&mut values, "id")?,
        user_id: required_string(&mut values, "userId")?,
        address: required_string(&mut values, "address")?,
        chain_id: required_number(&mut values, "chainId")?,
        created_at: required_date(&mut values, "createdAt")?,
        is_primary: required_bool(&mut values, "isPrimary")?,
    })
}

fn chain_id_value(chain_id: f64) -> Result<Value, AuthError> {
    if !chain_id.is_finite() || chain_id.fract() != 0.0 {
        return Err(AuthError::Storage(
            "SIWE chain ID must be a finite integer".into(),
        ));
    }
    let chain_id = chain_id as i64;
    i32::try_from(chain_id)
        .map(|chain_id| json!(chain_id))
        .map_err(|_| AuthError::Storage("SIWE chain ID exceeds the supported range".into()))
}

fn required_uuid(values: &mut Map<String, Value>, field: &str) -> Result<uuid::Uuid, AuthError> {
    let value = required_string(values, field)?;
    uuid::Uuid::parse_str(&value).map_err(|_| invalid_wallet_row(field))
}

fn required_string(values: &mut Map<String, Value>, field: &str) -> Result<String, AuthError> {
    take(values, field)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_wallet_row(field))
}

fn required_number(values: &mut Map<String, Value>, field: &str) -> Result<f64, AuthError> {
    take(values, field)?
        .as_f64()
        .ok_or_else(|| invalid_wallet_row(field))
}

fn required_bool(values: &mut Map<String, Value>, field: &str) -> Result<bool, AuthError> {
    take(values, field)?
        .as_bool()
        .ok_or_else(|| invalid_wallet_row(field))
}

fn required_date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
    let value = required_string(values, field)?;
    chrono::DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|_| invalid_wallet_row(field))
}

fn take(values: &mut Map<String, Value>, field: &str) -> Result<Value, AuthError> {
    values
        .remove(field)
        .ok_or_else(|| invalid_wallet_row(field))
}

fn invalid_wallet_row(field: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL SIWE wallet row has an invalid canonical '{field}' field"
    ))
}

pub(super) async fn insert_wallet_and_account(
    transaction: &mut Transaction<'_, Postgres>,
    wallet_model: &PostgresModel<'_>,
    account_model: &PostgresModel<'_>,
    wallet: &WalletAddress,
    account: &crate::OAuthAccount,
    account_id: &crate::PreparedDatabaseId,
) -> Result<(), AuthError> {
    let writes = wallet_model.encode_fields([
        ("id", json!(wallet.id.to_string())),
        ("userId", json!(wallet.user_id)),
        ("address", json!(wallet.address)),
        ("chainId", chain_id_value(wallet.chain_id)?),
        ("createdAt", json!(wallet.created_at.to_rfc3339())),
        ("isPrimary", json!(wallet.is_primary)),
    ])?;
    let mut query = insert_wallet_query(wallet_model, writes);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    super::super::oauth::insert_account_transaction(
        transaction,
        account_model,
        account,
        account_id,
    )
    .await?;
    Ok(())
}

fn insert_wallet_query(
    model: &PostgresModel<'_>,
    writes: Vec<super::super::PostgresWrite<'_>>,
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
    query.push(")");
    query
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog,
        PluginSchemaTable, ResolvedAdapterSchema,
    };
    use std::sync::Arc;

    #[test]
    fn wallet_queries_use_catalog_remaps_and_bound_values() {
        let mut table = PluginSchemaTable::new("walletAddress").model_name("tenant\"wallets");
        for (logical, physical, field_type) in [
            ("userId", "owner id", AdditionalFieldType::String),
            ("address", "wallet\"address", AdditionalFieldType::String),
            ("chainId", "network id", AdditionalFieldType::Number),
            ("createdAt", "created time", AdditionalFieldType::Date),
            ("isPrimary", "is primary", AdditionalFieldType::Boolean),
        ] {
            table = table.field(
                logical,
                AdditionalField::new(field_type).field_name(physical),
            );
        }
        let config = AuthConfig::new([18; 32]).unwrap();
        let catalog = Arc::new(AuthSchemaCatalog::build(&config, [table]).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        let physical =
            super::super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap();
        let model = physical.model("walletAddress").unwrap();

        let exact = wallet_query(&model, "0xsecret", Some(1.0)).unwrap();
        assert!(exact.sql().contains("FROM \"tenant\"\"wallets\""));
        assert!(
            exact
                .sql()
                .contains("lower(\"wallet\"\"address\") = lower($1)")
        );
        assert!(exact.sql().contains("\"network id\" = $2"));
        assert!(!exact.sql().contains("0xsecret"));

        let any = wallet_query(&model, "0xsecret", None).unwrap();
        assert!(
            any.sql()
                .contains("ORDER BY \"created time\" ASC, \"id\" ASC")
        );

        let writes = model
            .encode_fields([
                ("id", json!(uuid::Uuid::nil().to_string())),
                ("userId", json!(uuid::Uuid::nil().to_string())),
                ("address", json!("0xsecret")),
                ("chainId", json!(1)),
                ("createdAt", json!(chrono::Utc::now().to_rfc3339())),
                ("isPrimary", json!(true)),
            ])
            .unwrap();
        let insert = insert_wallet_query(&model, writes);
        assert!(insert.sql().contains("INSERT INTO \"tenant\"\"wallets\""));
        assert!(insert.sql().contains("\"owner id\""));
        assert_eq!(insert.sql().matches('$').count(), 6);
        assert!(!insert.sql().contains("0xsecret"));
    }

    #[test]
    fn chain_ids_must_fit_the_catalog_integer_type() {
        assert_eq!(chain_id_value(1.0).unwrap(), json!(1));
        assert!(chain_id_value(1.5).is_err());
        assert!(chain_id_value(f64::NAN).is_err());
        assert!(chain_id_value(f64::from(i32::MAX) + 1.0).is_err());
    }

    #[test]
    fn required_wallet_fields_reject_null_values() {
        let mut values = Map::from_iter([("id".into(), Value::Null)]);
        assert!(required_uuid(&mut values, "id").is_err());
        let mut values = Map::from_iter([("isPrimary".into(), Value::Null)]);
        assert!(required_bool(&mut values, "isPrimary").is_err());
        let mut values = Map::from_iter([("createdAt".into(), Value::Null)]);
        assert!(required_date(&mut values, "createdAt").is_err());
    }
}
