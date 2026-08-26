use super::{PostgresModel, PostgresStore, storage_error};
use crate::{
    AuthError, SiweIdentityWrite, SiweIdentityWriteOutcome, SiweSchema, SiweStore, WalletAddress,
    WalletAddressOwner,
};
use async_trait::async_trait;
use sqlx::{Postgres, QueryBuilder, Transaction};

mod query;

use query::{find_owner_tx, find_wallet_pool, insert_wallet_and_account};

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
            .load_user_by_id(wallet.user_id)
            .await?
            .ok_or_else(|| AuthError::Storage("SIWE wallet owner is missing".into()))?;
        Ok(Some(WalletAddressOwner { wallet, user }))
    }

    async fn write_wallet_identity(
        &self,
        _schema: &SiweSchema,
        write: SiweIdentityWrite,
    ) -> Result<SiweIdentityWriteOutcome, AuthError> {
        let models = IdentityWriteModels {
            wallet: self.physical_model("walletAddress")?,
            user: self.user_model()?,
            account: self.physical_model("account")?,
        };
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let (wallet, account) = match &write {
            SiweIdentityWrite::Create {
                wallet, account, ..
            }
            | SiweIdentityWrite::AddChain {
                wallet, account, ..
            } => (wallet.clone(), account.as_ref().clone()),
        };
        let mut lock = QueryBuilder::new("SELECT pg_advisory_xact_lock(hashtextextended(lower(");
        lock.push_bind(wallet.address.clone()).push("), 0))");
        lock.build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        if let Some(owner) = find_owner_tx(
            &mut transaction,
            &models.wallet,
            &models.user,
            &wallet.address,
            Some(wallet.chain_id),
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
            &wallet.address,
            None,
        )
        .await?;
        let outcome = perform_identity_write(
            &mut transaction,
            &models,
            write,
            wallet,
            account,
            address_owner,
        )
        .await?;
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
    async fn insert(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        wallet: &WalletAddress,
        account: &crate::OAuthAccount,
    ) -> Result<(), AuthError> {
        insert_wallet_and_account(transaction, &self.wallet, &self.account, wallet, account).await
    }
}

async fn perform_identity_write(
    transaction: &mut Transaction<'_, Postgres>,
    models: &IdentityWriteModels<'_>,
    write: SiweIdentityWrite,
    mut wallet: WalletAddress,
    mut account: crate::OAuthAccount,
    address_owner: Option<WalletAddressOwner>,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    match write {
        SiweIdentityWrite::Create { mut user, .. } => {
            if let Some(owner) = address_owner {
                wallet.user_id = owner.user.id;
                wallet.is_primary = false;
                account.user_id = owner.user.id;
                models.insert(transaction, &wallet, &account).await?;
                return Ok(SiweIdentityWriteOutcome::AddedChain {
                    user: owner.user,
                    wallet,
                    account,
                });
            }
            user.email = user.email.to_lowercase();
            if super::user::email_exists_transaction(transaction, &models.user, &user.email).await?
            {
                return Ok(SiweIdentityWriteOutcome::EmailTaken);
            }
            wallet.user_id = user.id;
            wallet.is_primary = true;
            account.user_id = user.id;
            let user = super::user::insert_transaction(transaction, &models.user, *user).await?;
            models.insert(transaction, &wallet, &account).await?;
            Ok(SiweIdentityWriteOutcome::Created {
                user,
                wallet,
                account,
            })
        }
        SiweIdentityWrite::AddChain {
            expected_user_id, ..
        } => {
            let Some(owner) = address_owner else {
                return Err(AuthError::Storage(
                    "SIWE address owner disappeared during chain linking".into(),
                ));
            };
            if owner.user.id != expected_user_id {
                return Ok(SiweIdentityWriteOutcome::Existing(owner));
            }
            wallet.user_id = owner.user.id;
            wallet.is_primary = false;
            account.user_id = owner.user.id;
            models.insert(transaction, &wallet, &account).await?;
            Ok(SiweIdentityWriteOutcome::AddedChain {
                user: owner.user,
                wallet,
                account,
            })
        }
    }
}
