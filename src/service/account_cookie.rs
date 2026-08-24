use super::{
    AuthService,
    account_lifecycle::require_account_session,
    account_types::{ProviderAccountInfo, ProviderTokenResponse},
};
use crate::{AuthError, OAuthAccount, SessionWithUser};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ACCOUNT_COOKIE_SALT: &[u8] = b"better-auth-account";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountCookiePayload {
    id: Uuid,
    user_id: Uuid,
    issuer: String,
    account_id: String,
    provider_id: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
    scope: Option<String>,
    #[serde(flatten)]
    additional_fields: serde_json::Map<String, serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<OAuthAccount> for AccountCookiePayload {
    fn from(account: OAuthAccount) -> Self {
        Self {
            id: account.id,
            user_id: account.user_id,
            issuer: account.issuer,
            account_id: account.account_id,
            provider_id: account.provider_id,
            access_token: account.access_token,
            refresh_token: account.refresh_token,
            id_token: account.id_token,
            access_token_expires_at: account.access_token_expires_at,
            refresh_token_expires_at: account.refresh_token_expires_at,
            scope: account.scope,
            additional_fields: account.additional_fields,
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

impl From<AccountCookiePayload> for OAuthAccount {
    fn from(account: AccountCookiePayload) -> Self {
        Self {
            id: account.id,
            user_id: account.user_id,
            issuer: account.issuer,
            account_id: account.account_id,
            provider_id: account.provider_id,
            access_token: account.access_token,
            refresh_token: account.refresh_token,
            id_token: account.id_token,
            access_token_expires_at: account.access_token_expires_at,
            refresh_token_expires_at: account.refresh_token_expires_at,
            scope: account.scope,
            password: None,
            additional_fields: account.additional_fields,
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

impl AuthService {
    pub(crate) fn account_cookie_enabled(&self) -> bool {
        self.config.account.store_account_cookie
    }

    pub(crate) fn account_data_cookie(&self) -> crate::cookie::ResolvedCookie {
        self.resolve_cookie(crate::cookie::CookieKind::AccountData)
    }

    pub(crate) fn encode_account_cookie(&self, account: OAuthAccount) -> Result<String, AuthError> {
        crate::symmetric_jwe::encode(
            AccountCookiePayload::from(account),
            &self.config.secret,
            ACCOUNT_COOKIE_SALT,
            self.cookie_cache_max_age(),
        )
    }

    pub(crate) fn decode_account_cookie(&self, value: &str) -> Option<OAuthAccount> {
        crate::symmetric_jwe::decode::<AccountCookiePayload>(
            value,
            &self.config.secret,
            ACCOUNT_COOKIE_SALT,
        )
        .map(|(account, _)| account.into())
    }

    pub(crate) async fn get_provider_access_token_from_cookie(
        &self,
        actor: &SessionWithUser,
        account: OAuthAccount,
    ) -> Result<ProviderTokenResponse, AuthError> {
        require_cookie_account(actor, &account)?;
        self.get_provider_access_token_for_account(account).await
    }

    pub(crate) async fn refresh_provider_access_token_from_cookie(
        &self,
        actor: &SessionWithUser,
        account: OAuthAccount,
    ) -> Result<ProviderTokenResponse, AuthError> {
        require_cookie_account(actor, &account)?;
        self.refresh_provider_account(account).await
    }

    pub(crate) async fn provider_account_info_from_cookie(
        &self,
        actor: &SessionWithUser,
        account: OAuthAccount,
    ) -> Result<ProviderAccountInfo, AuthError> {
        require_cookie_account(actor, &account)?;
        self.provider_account_info_for_account(account).await
    }

    pub(crate) async fn account_cookie_for_provider(
        &self,
        user_id: Uuid,
        provider_id: &str,
    ) -> Result<Option<OAuthAccount>, AuthError> {
        Ok(self
            .store
            .list_user_accounts(user_id)
            .await?
            .into_iter()
            .filter(|account| account.provider_id == provider_id)
            .max_by_key(|account| account.updated_at))
    }

    pub(crate) async fn account_cookie_for_id(
        &self,
        user_id: Uuid,
        account_id: Uuid,
    ) -> Result<Option<OAuthAccount>, AuthError> {
        Ok(self
            .store
            .list_user_accounts(user_id)
            .await?
            .into_iter()
            .find(|account| account.id == account_id))
    }
}

fn require_cookie_account(
    actor: &SessionWithUser,
    account: &OAuthAccount,
) -> Result<(), AuthError> {
    require_account_session(actor)?;
    if account.user_id == actor.user.id {
        Ok(())
    } else {
        Err(AuthError::AccountNotFound)
    }
}
