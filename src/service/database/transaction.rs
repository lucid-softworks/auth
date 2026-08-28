use super::{AuthError, AuthService, DatabaseRecord, DatabaseWrite};
use crate::service::database::create::UserAccountCreate;

impl AuthService {
    pub(in crate::service) async fn create_user_and_credential_account(
        &self,
        user: crate::AuthUser,
        password_hash: String,
    ) -> Result<crate::OAuthAccountOwner, AuthError> {
        let now = user.created_at;
        self.create_user_and_account(user, UserAccountCreate::Credential { password_hash, now })
            .await
    }

    pub(in crate::service) async fn create_user_and_oauth_account(
        &self,
        user: crate::AuthUser,
        account: crate::OAuthAccount,
    ) -> Result<crate::OAuthAccountOwner, AuthError> {
        self.create_user_and_account(user, UserAccountCreate::OAuth(Box::new(account)))
            .await
    }

    async fn create_user_and_account(
        &self,
        user: crate::AuthUser,
        account: UserAccountCreate,
    ) -> Result<crate::OAuthAccountOwner, AuthError> {
        let service = self.clone();
        let store = self.store.clone();
        let owner = crate::run_database_transaction(store.as_ref(), move |transaction| {
            Box::pin(async move {
                let user = service.prepare_user_create(user).await?;
                let DatabaseRecord::User(user) = transaction
                    .create(crate::DatabaseCreateOperation::User(user))
                    .await?
                else {
                    unreachable!("transaction create preserves its model")
                };
                let account = account.prepare(&service, &user).await?;
                let DatabaseRecord::Account(account) = transaction
                    .create(crate::DatabaseCreateOperation::Account(account))
                    .await?
                else {
                    unreachable!("transaction create preserves its model")
                };
                Ok(crate::OAuthAccountOwner { account, user })
            })
        })
        .await?;
        self.finish_user_create(&owner.user).await?;
        self.finish_account_create(&owner.account).await?;
        Ok(owner)
    }

    pub(in crate::service) async fn upsert_user_and_credential_account(
        &self,
        original: Option<crate::AuthUser>,
        candidate: crate::AuthUser,
        password_hash: String,
    ) -> Result<crate::DatabaseAccountOwnerWrite, AuthError> {
        let existing_account = match &original {
            Some(user) => self
                .store
                .find_oauth_account_owner("local:credential", &user.id)
                .await?
                .map(|owner| owner.account),
            None => None,
        };
        let service = self.clone();
        let store = self.store.clone();
        let write = crate::run_database_transaction(store.as_ref(), move |transaction| {
            Box::pin(async move {
                let (user, user_operation) = service
                    .write_transaction_user(transaction.as_ref(), original, candidate)
                    .await?;
                let account = service
                    .prepare_credential_account(
                        user.id.clone(),
                        password_hash,
                        user.created_at,
                        existing_account.as_ref(),
                    )
                    .await?;
                let (account, account_operation) =
                    write_transaction_account(transaction.as_ref(), account).await?;
                Ok(crate::DatabaseAccountOwnerWrite {
                    owner: crate::OAuthAccountOwner { account, user },
                    user_operation,
                    account_operation,
                })
            })
        })
        .await?;
        self.finish_account_owner_write(&write).await?;
        Ok(write)
    }

    async fn write_transaction_user(
        &self,
        transaction: &dyn crate::DatabaseTransaction,
        original: Option<crate::AuthUser>,
        candidate: crate::AuthUser,
    ) -> Result<(crate::AuthUser, crate::DatabaseWriteOperation), AuthError> {
        match original {
            Some(original) => {
                let user = self.prepare_user_update(&original, candidate).await?;
                let DatabaseRecord::User(user) =
                    transaction.update(DatabaseRecord::User(user)).await?
                else {
                    unreachable!("transaction update preserves its model")
                };
                Ok((user, crate::DatabaseWriteOperation::Update))
            }
            None => {
                let user = self.prepare_user_create(candidate).await?;
                let DatabaseRecord::User(user) = transaction
                    .create(crate::DatabaseCreateOperation::User(user))
                    .await?
                else {
                    unreachable!("transaction create preserves its model")
                };
                Ok((user, crate::DatabaseWriteOperation::Create))
            }
        }
    }

    async fn finish_account_owner_write(
        &self,
        write: &crate::DatabaseAccountOwnerWrite,
    ) -> Result<(), AuthError> {
        match write.user_operation {
            crate::DatabaseWriteOperation::Create => {
                self.finish_user_create(&write.owner.user).await?
            }
            crate::DatabaseWriteOperation::Update => {
                self.after_database_update(&DatabaseRecord::User(write.owner.user.clone()))
                    .await?;
            }
        }
        match write.account_operation {
            crate::DatabaseWriteOperation::Create => {
                self.finish_account_create(&write.owner.account).await?
            }
            crate::DatabaseWriteOperation::Update => {
                self.finish_account_update(&write.owner.account).await?
            }
        }
        Ok(())
    }
}

async fn write_transaction_account(
    transaction: &dyn crate::DatabaseTransaction,
    account: DatabaseWrite<crate::OAuthAccount>,
) -> Result<(crate::OAuthAccount, crate::DatabaseWriteOperation), AuthError> {
    match account {
        DatabaseWrite::Create(account) => {
            let DatabaseRecord::Account(account) = transaction
                .create(crate::DatabaseCreateOperation::Account(account))
                .await?
            else {
                unreachable!("transaction create preserves its model")
            };
            Ok((account, crate::DatabaseWriteOperation::Create))
        }
        DatabaseWrite::Update(account) => {
            let DatabaseRecord::Account(account) =
                transaction.update(DatabaseRecord::Account(account)).await?
            else {
                unreachable!("transaction update preserves its model")
            };
            Ok((account, crate::DatabaseWriteOperation::Update))
        }
    }
}
