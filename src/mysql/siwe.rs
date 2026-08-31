use super::{MySqlComparisonMode, MySqlFilter, MySqlStore, codec, oauth, query::execute};
use crate::{
    AuthError, AuthUser, DatabaseAccountCreate, DatabaseCreate, OAuthAccount, SiweIdentityWrite,
    SiweIdentityWriteOutcome, SiweSchema, SiweStore, WalletAddress, WalletAddressOwner,
};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sqlx::{MySql, Transaction};

#[async_trait]
impl SiweStore for MySqlStore {
    async fn find_wallet_owner(
        &self,
        _schema: &SiweSchema,
        address: &str,
        chain_id: Option<f64>,
    ) -> Result<Option<WalletAddressOwner>, AuthError> {
        let Some(wallet) = find_wallet(self, address, chain_id).await? else {
            return Ok(None);
        };
        let user = super::user::find(self, "id", &wallet.user_id)
            .await?
            .ok_or_else(|| AuthError::Storage("SIWE wallet owner is missing".into()))?;
        Ok(Some(WalletAddressOwner { wallet, user }))
    }

    async fn create_wallet_identity(
        &self,
        _schema: &SiweSchema,
        user: DatabaseCreate<AuthUser>,
        wallet: DatabaseCreate<WalletAddress>,
        account: &dyn DatabaseAccountCreate,
    ) -> Result<SiweIdentityWriteOutcome, AuthError> {
        create_identity(self, user, wallet, account).await
    }

    async fn write_wallet_identity(
        &self,
        _schema: &SiweSchema,
        write: SiweIdentityWrite,
    ) -> Result<SiweIdentityWriteOutcome, AuthError> {
        add_chain(self, write).await
    }
}

async fn create_identity(
    store: &MySqlStore,
    user: DatabaseCreate<AuthUser>,
    mut wallet: DatabaseCreate<WalletAddress>,
    account: &dyn DatabaseAccountCreate,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(storage)?;
    if let Some(owner) = owner_tx(
        &mut transaction,
        schema,
        &wallet.record.address,
        Some(wallet.record.chain_id),
    )
    .await?
    {
        transaction.commit().await.map_err(storage)?;
        return Ok(SiweIdentityWriteOutcome::Existing(owner));
    }
    let address_owner = owner_tx(&mut transaction, schema, &wallet.record.address, None).await?;
    let outcome = if let Some(owner) = address_owner {
        let mut account = account.prepare(&owner.user).await?;
        wallet.record.user_id = owner.user.id.clone();
        wallet.record.is_primary = false;
        account.record.user_id = owner.user.id.clone();
        let (wallet, account) =
            insert_pair(store, &mut transaction, schema, wallet, account).await?;
        SiweIdentityWriteOutcome::AddedChain {
            user: owner.user,
            wallet,
            account,
        }
    } else {
        let (mut user, user_id) = user.into_parts(store)?;
        user.email = user.email.to_lowercase();
        let mut email = MySqlFilter::equal("email", json!(user.email));
        email.mode = MySqlComparisonMode::Insensitive;
        if execute::find_one(&mut transaction, schema, "user", &[email], &[])
            .await?
            .is_some()
        {
            transaction.commit().await.map_err(storage)?;
            return Ok(SiweIdentityWriteOutcome::EmailTaken);
        }
        let record = codec::create_record(store, "user", &user, &user_id)?;
        let user = codec::decode::<AuthUser>(
            "user",
            execute::insert_required(&mut transaction, schema, "user", record).await?,
        )?;
        let mut account = account.prepare(&user).await?;
        wallet.record.user_id = user.id.clone();
        wallet.record.is_primary = true;
        account.record.user_id = user.id.clone();
        let (wallet, account) =
            insert_pair(store, &mut transaction, schema, wallet, account).await?;
        SiweIdentityWriteOutcome::Created {
            user,
            wallet,
            account,
        }
    };
    transaction.commit().await.map_err(storage)?;
    Ok(outcome)
}

async fn add_chain(
    store: &MySqlStore,
    write: SiweIdentityWrite,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    let SiweIdentityWrite::AddChain {
        expected_user_id,
        mut wallet,
        mut account,
    } = write;
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(storage)?;
    if let Some(owner) = owner_tx(
        &mut transaction,
        schema,
        &wallet.record.address,
        Some(wallet.record.chain_id),
    )
    .await?
    {
        transaction.commit().await.map_err(storage)?;
        return Ok(SiweIdentityWriteOutcome::Existing(owner));
    }
    let owner = owner_tx(&mut transaction, schema, &wallet.record.address, None)
        .await?
        .ok_or_else(|| {
            AuthError::Storage("SIWE address owner disappeared during chain linking".into())
        })?;
    if owner.user.id != expected_user_id {
        transaction.commit().await.map_err(storage)?;
        return Ok(SiweIdentityWriteOutcome::Existing(owner));
    }
    wallet.record.user_id = owner.user.id.clone();
    wallet.record.is_primary = false;
    account.record.user_id = owner.user.id.clone();
    let (wallet, account) = insert_pair(store, &mut transaction, schema, wallet, account).await?;
    transaction.commit().await.map_err(storage)?;
    Ok(SiweIdentityWriteOutcome::AddedChain {
        user: owner.user,
        wallet,
        account,
    })
}

async fn insert_pair(
    store: &MySqlStore,
    transaction: &mut Transaction<'_, MySql>,
    schema: &super::schema::MySqlSchema,
    wallet: DatabaseCreate<WalletAddress>,
    account: DatabaseCreate<OAuthAccount>,
) -> Result<(WalletAddress, OAuthAccount), AuthError> {
    let (wallet, wallet_id) = wallet.into_parts(store)?;
    let (account, account_id) = account.into_parts(store)?;
    let wallet = insert_wallet(store, transaction, schema, wallet, wallet_id).await?;
    let account = oauth::insert_transaction(store, transaction, schema, account, account_id)
        .await
        .map_err(account_error)?;
    Ok((wallet, account))
}

async fn insert_wallet(
    _store: &MySqlStore,
    transaction: &mut Transaction<'_, MySql>,
    schema: &super::schema::MySqlSchema,
    wallet: WalletAddress,
    id: crate::PreparedDatabaseId,
) -> Result<WalletAddress, AuthError> {
    let mut values = wallet_values(&wallet);
    if let crate::PreparedDatabaseId::Value(value) = id {
        values.insert("id".into(), value.to_json()?);
    }
    decode_wallet(execute::insert_required(transaction, schema, "walletAddress", values).await?)
}

async fn find_wallet(
    store: &MySqlStore,
    address: &str,
    chain_id: Option<f64>,
) -> Result<Option<WalletAddress>, AuthError> {
    let filters = wallet_filters(address, chain_id);
    store
        .find_record("walletAddress", &filters, &[])
        .await?
        .map(decode_wallet)
        .transpose()
}

async fn owner_tx(
    transaction: &mut Transaction<'_, MySql>,
    schema: &super::schema::MySqlSchema,
    address: &str,
    chain_id: Option<f64>,
) -> Result<Option<WalletAddressOwner>, AuthError> {
    let Some(wallet) = execute::find_one(
        transaction,
        schema,
        "walletAddress",
        &wallet_filters(address, chain_id),
        &[],
    )
    .await?
    .map(decode_wallet)
    .transpose()?
    else {
        return Ok(None);
    };
    let user = execute::find_one(
        transaction,
        schema,
        "user",
        &[MySqlFilter::equal("id", json!(wallet.user_id))],
        &[],
    )
    .await?
    .map(|record| codec::decode("user", record))
    .transpose()?
    .ok_or_else(|| AuthError::Storage("SIWE wallet owner is missing".into()))?;
    Ok(Some(WalletAddressOwner { wallet, user }))
}

fn wallet_filters(address: &str, chain_id: Option<f64>) -> Vec<MySqlFilter> {
    let mut filters = vec![MySqlFilter::equal("address", json!(address))];
    if let Some(chain_id) = chain_id {
        filters.push(MySqlFilter::equal("chainId", json!(chain_id)));
    }
    filters
}

fn wallet_values(wallet: &WalletAddress) -> Map<String, Value> {
    Map::from_iter([
        ("userId".into(), json!(wallet.user_id)),
        ("address".into(), json!(wallet.address)),
        ("chainId".into(), json!(wallet.chain_id)),
        ("isPrimary".into(), json!(wallet.is_primary)),
        ("createdAt".into(), json!(wallet.created_at)),
    ])
}

fn decode_wallet(mut values: Map<String, Value>) -> Result<WalletAddress, AuthError> {
    Ok(WalletAddress {
        id: string(&mut values, "id")?,
        user_id: string(&mut values, "userId")?,
        address: string(&mut values, "address")?,
        chain_id: values
            .remove("chainId")
            .and_then(|value| value.as_f64())
            .ok_or_else(|| invalid("chainId"))?,
        is_primary: values
            .remove("isPrimary")
            .and_then(|value| value.as_bool())
            .ok_or_else(|| invalid("isPrimary"))?,
        created_at: date(&mut values, "createdAt")?,
    })
}

fn string(values: &mut Map<String, Value>, field: &str) -> Result<String, AuthError> {
    values
        .remove(field)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid(field))
}
fn date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
    chrono::DateTime::parse_from_rfc3339(&string(values, field)?)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|_| invalid(field))
}
fn account_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Storage(message) if message.contains("UNIQUE constraint failed") => {
            AuthError::UserAlreadyExists
        }
        error => error,
    }
}
fn invalid(field: &str) -> AuthError {
    AuthError::Storage(format!("invalid MySQL walletAddress row: {field}"))
}
fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
