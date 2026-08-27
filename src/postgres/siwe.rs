use super::{PostgresModel, PostgresStore, storage_error};
use crate::{
    AuthError, AuthUser, DatabaseAccountCreate, DatabaseCreate, SiweIdentityWrite,
    SiweIdentityWriteOutcome, SiweSchema, SiweStore, WalletAddress, WalletAddressOwner,
};
use async_trait::async_trait;
use sqlx::{Postgres, QueryBuilder, Transaction};

mod query;

use query::{account_exists_tx, find_owner_tx, find_wallet_pool, insert_wallet_and_account};

#[async_trait]
impl SiweStore for PostgresStore {
    async fn find_wallet_owner(
        &self,
        _schema: &SiweSchema,
        address: &str,
        chain_id: Option<f64>,
    ) -> Result<Option<WalletAddressOwner>, AuthError> {
        let wallet_model = self.physical_model("walletAddress")?;
        let wallet = find_wallet_pool(&self.pool, &wallet_model, address, chain_id).await?;
        let Some(wallet) = wallet else {
            return Ok(None);
        };
        let user = self
            .load_user_by_id(&wallet.user_id)
            .await?
            .ok_or_else(|| AuthError::Storage("SIWE wallet owner is missing".into()))?;
        Ok(Some(WalletAddressOwner { wallet, user }))
    }

    async fn create_wallet_identity(
        &self,
        _schema: &SiweSchema,
        user: DatabaseCreate<AuthUser>,
        mut wallet: DatabaseCreate<WalletAddress>,
        account: &dyn DatabaseAccountCreate,
    ) -> Result<SiweIdentityWriteOutcome, AuthError> {
        let models = IdentityWriteModels::new(self)?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        lock_address(&mut transaction, &wallet.record.address).await?;
        if let Some(owner) = find_owner_tx(
            &mut transaction,
            &models.wallet,
            &models.user,
            &wallet.record.address,
            Some(wallet.record.chain_id),
        )
        .await?
        {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(SiweIdentityWriteOutcome::Existing(owner));
        }
        let address_owner = find_owner_tx(
            &mut transaction,
            &models.wallet,
            &models.user,
            &wallet.record.address,
            None,
        )
        .await?;

        let outcome = if let Some(owner) = address_owner {
            let account = account.prepare(&owner.user).await?;
            wallet.record.user_id = owner.user.id.clone();
            wallet.record.is_primary = false;
            let mut account = account;
            account.record.user_id = owner.user.id.clone();
            let (wallet, account) = models
                .insert(self, &mut transaction, wallet, account)
                .await?;
            SiweIdentityWriteOutcome::AddedChain {
                user: owner.user,
                wallet,
                account,
            }
        } else {
            let DatabaseCreate {
                record: mut user,
                id: user_id,
            } = user;
            user.email = user.email.to_lowercase();
            if super::user::email_exists_transaction(&mut transaction, &models.user, &user.email)
                .await?
            {
                transaction.commit().await.map_err(storage_error)?;
                return Ok(SiweIdentityWriteOutcome::EmailTaken);
            }
            let user_id = user_id.prepare(self)?;
            let user =
                super::user::insert_transaction(&mut transaction, &models.user, user, &user_id)
                    .await?;
            let account = account.prepare(&user).await?;
            wallet.record.user_id = user.id.clone();
            wallet.record.is_primary = true;
            let mut account = account;
            account.record.user_id = user.id.clone();
            let (wallet, account) = models
                .insert(self, &mut transaction, wallet, account)
                .await?;
            SiweIdentityWriteOutcome::Created {
                user,
                wallet,
                account,
            }
        };
        transaction.commit().await.map_err(storage_error)?;
        Ok(outcome)
    }

    async fn write_wallet_identity(
        &self,
        _schema: &SiweSchema,
        write: SiweIdentityWrite,
    ) -> Result<SiweIdentityWriteOutcome, AuthError> {
        let models = IdentityWriteModels::new(self)?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let (wallet, account) = match &write {
            SiweIdentityWrite::AddChain {
                wallet, account, ..
            } => (wallet.clone(), account.clone()),
        };
        lock_address(&mut transaction, &wallet.record.address).await?;
        if let Some(owner) = find_owner_tx(
            &mut transaction,
            &models.wallet,
            &models.user,
            &wallet.record.address,
            Some(wallet.record.chain_id),
        )
        .await?
        {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(SiweIdentityWriteOutcome::Existing(owner));
        }
        let address_owner = find_owner_tx(
            &mut transaction,
            &models.wallet,
            &models.user,
            &wallet.record.address,
            None,
        )
        .await?;
        let SiweIdentityWrite::AddChain {
            expected_user_id, ..
        } = write;
        let Some(owner) = address_owner else {
            return Err(AuthError::Storage(
                "SIWE address owner disappeared during chain linking".into(),
            ));
        };
        if owner.user.id != expected_user_id {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(SiweIdentityWriteOutcome::Existing(owner));
        }
        let mut wallet = wallet;
        wallet.record.user_id = owner.user.id.clone();
        wallet.record.is_primary = false;
        let mut account = account;
        account.record.user_id = owner.user.id.clone();
        let (wallet, account) = models
            .insert(self, &mut transaction, wallet, account)
            .await?;
        let outcome = SiweIdentityWriteOutcome::AddedChain {
            user: owner.user,
            wallet,
            account,
        };
        transaction.commit().await.map_err(storage_error)?;
        Ok(outcome)
    }
}

struct IdentityWriteModels<'a> {
    wallet: PostgresModel<'a>,
    user: PostgresModel<'a>,
    account: PostgresModel<'a>,
}

impl IdentityWriteModels<'_> {
    fn new(store: &PostgresStore) -> Result<IdentityWriteModels<'_>, AuthError> {
        Ok(IdentityWriteModels {
            wallet: store.physical_model("walletAddress")?,
            user: store.user_model()?,
            account: store.physical_model("account")?,
        })
    }

    async fn insert(
        &self,
        store: &PostgresStore,
        transaction: &mut Transaction<'_, Postgres>,
        wallet: DatabaseCreate<WalletAddress>,
        account: DatabaseCreate<crate::OAuthAccount>,
    ) -> Result<(WalletAddress, crate::OAuthAccount), AuthError> {
        if account_exists_tx(
            transaction,
            &self.account,
            &account.record.issuer,
            &account.record.account_id,
        )
        .await?
        {
            return Err(AuthError::UserAlreadyExists);
        }
        let (wallet, wallet_id) = wallet.into_parts(store)?;
        let (account, account_id) = account.into_parts(store)?;
        insert_wallet_and_account(
            transaction,
            &self.wallet,
            &self.account,
            &wallet,
            &wallet_id,
            &account,
            &account_id,
        )
        .await
    }
}

async fn lock_address(
    transaction: &mut Transaction<'_, Postgres>,
    address: &str,
) -> Result<(), AuthError> {
    let mut lock = QueryBuilder::new("SELECT pg_advisory_xact_lock(hashtextextended(lower(");
    lock.push_bind(address.to_owned()).push("), 0))");
    lock.build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(())
}
