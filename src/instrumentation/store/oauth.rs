use super::InstrumentedAuthStore;
use crate::{
    AccountDeleteOutcome, AuthError, OAuthAccount, OAuthAccountOwner, OAuthAccountStore,
    OAuthTokenUpdateOutcome, DatabaseCreate, DependentAccountPreparer,
    instrumentation::{AdapterOperation, with_adapter_operation},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OAuthAccountStore for InstrumentedAuthStore {
    async fn find_oauth_account_owner(
        &self,
        issuer: &str,
        account_id: &str,
    ) -> Result<Option<OAuthAccountOwner>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "account",
            self.inner.find_oauth_account_owner(issuer, account_id),
        )
        .await
    }

    async fn create_oauth_user(
        &self,
        user: DatabaseCreate<crate::AuthUser>,
        account: &dyn DependentAccountPreparer,
    ) -> Result<OAuthAccountOwner, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "user",
            self.inner.create_oauth_user(user, account),
        )
        .await
    }

    async fn link_oauth_account(
        &self,
        account: DatabaseCreate<OAuthAccount>,
    ) -> Result<OAuthAccount, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "account",
            self.inner.link_oauth_account(account),
        )
        .await
    }

    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "account",
            self.inner.update_oauth_account_tokens(account),
        )
        .await
    }

    async fn list_user_accounts(&self, user_id: &str) -> Result<Vec<OAuthAccount>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindMany,
            "account",
            self.inner.list_user_accounts(user_id),
        )
        .await
    }

    async fn delete_user_account(
        &self,
        user_id: &str,
        account_id: &str,
        allow_last: bool,
    ) -> Result<AccountDeleteOutcome, AuthError> {
        with_adapter_operation(
            AdapterOperation::Delete,
            "account",
            self.inner
                .delete_user_account(user_id, account_id, allow_last),
        )
        .await
    }

    async fn compare_and_swap_oauth_tokens(
        &self,
        account: OAuthAccount,
        expected_refresh_token: Option<&str>,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<OAuthTokenUpdateOutcome, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "account",
            self.inner.compare_and_swap_oauth_tokens(
                account,
                expected_refresh_token,
                expected_updated_at,
            ),
        )
        .await
    }
}
