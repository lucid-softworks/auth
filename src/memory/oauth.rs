use super::{MemoryStore, phone_number};
use crate::{
    AccountDeleteOutcome, AuthError, AuthUser, OAuthAccount, OAuthAccountOwner,
    OAuthTokenUpdateOutcome,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait::async_trait]
impl crate::OAuthAccountStore for MemoryStore {
    async fn find_oauth_account_owner(
        &self,
        issuer: &str,
        account_id: &str,
    ) -> Result<Option<crate::OAuthAccountOwner>, AuthError> {
        find_owner(self, issuer, account_id).await
    }
    async fn create_oauth_user(
        &self,
        user: AuthUser,
        account: OAuthAccount,
    ) -> Result<crate::OAuthAccountOwner, AuthError> {
        create_user(self, user, account).await
    }
    async fn link_oauth_account(&self, account: OAuthAccount) -> Result<OAuthAccount, AuthError> {
        link(self, account).await
    }
    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError> {
        update_tokens(self, account).await
    }
    async fn list_user_accounts(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AuthError> {
        list(self, user_id).await
    }
    async fn delete_user_account(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        allow_last: bool,
    ) -> Result<AccountDeleteOutcome, AuthError> {
        delete(self, user_id, account_id, allow_last).await
    }
    async fn compare_and_swap_oauth_tokens(
        &self,
        account: OAuthAccount,
        expected_refresh_token: Option<&str>,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<OAuthTokenUpdateOutcome, AuthError> {
        compare_and_swap_tokens(self, account, expected_refresh_token, expected_updated_at).await
    }
}

pub(super) async fn find_owner(
    store: &MemoryStore,
    issuer: &str,
    account_id: &str,
) -> Result<Option<OAuthAccountOwner>, AuthError> {
    let state = store.state.read().await;
    let Some(account) = state
        .oauth_accounts
        .get(&(issuer.to_owned(), account_id.to_owned()))
    else {
        return Ok(None);
    };
    let user = state
        .users
        .get(&account.user_id)
        .ok_or_else(|| AuthError::Storage("OAuth account owner is missing".into()))?;
    Ok(Some(OAuthAccountOwner {
        account: account.clone(),
        user: user.clone(),
    }))
}

pub(super) async fn create_user(
    store: &MemoryStore,
    mut user: AuthUser,
    mut account: OAuthAccount,
) -> Result<OAuthAccountOwner, AuthError> {
    user.email = user.email.to_lowercase();
    let mut state = store.state.write().await;
    let key = (account.issuer.clone(), account.account_id.clone());
    if state.oauth_accounts.contains_key(&key) || state.emails.contains_key(&user.email) {
        return Err(AuthError::UserAlreadyExists);
    }
    if phone_number::user_phone_number(&user)?.is_some_and(|phone_number| {
        !phone_number::phone_number_available(&state, phone_number, None)
    }) {
        return Err(AuthError::UserAlreadyExists);
    }
    account.user_id = user.id;
    state.emails.insert(user.email.clone(), user.id);
    phone_number::index_phone_number(&mut state, &user)?;
    state.users.insert(user.id, user.clone());
    state.oauth_accounts.insert(key, account.clone());
    Ok(OAuthAccountOwner { account, user })
}

pub(super) async fn link(
    store: &MemoryStore,
    account: OAuthAccount,
) -> Result<OAuthAccount, AuthError> {
    let mut state = store.state.write().await;
    if !state.users.contains_key(&account.user_id) {
        return Err(AuthError::NotFound);
    }
    let key = (account.issuer.clone(), account.account_id.clone());
    if state.oauth_accounts.contains_key(&key) {
        return Err(AuthError::UserAlreadyExists);
    }
    state.oauth_accounts.insert(key, account.clone());
    Ok(account)
}

pub(super) async fn update_tokens(
    store: &MemoryStore,
    account: OAuthAccount,
) -> Result<OAuthAccount, AuthError> {
    let mut state = store.state.write().await;
    let key = (account.issuer.clone(), account.account_id.clone());
    let stored = state
        .oauth_accounts
        .get_mut(&key)
        .ok_or(AuthError::NotFound)?;
    if stored.id != account.id || stored.user_id != account.user_id {
        return Err(AuthError::Forbidden);
    }
    *stored = account.clone();
    Ok(account)
}

pub(super) async fn list(
    store: &MemoryStore,
    user_id: Uuid,
) -> Result<Vec<OAuthAccount>, AuthError> {
    let mut accounts = store
        .state
        .read()
        .await
        .oauth_accounts
        .values()
        .filter(|account| account.user_id == user_id)
        .cloned()
        .collect::<Vec<_>>();
    accounts.sort_by_key(|account| (account.created_at, account.id));
    Ok(accounts)
}

pub(super) async fn delete(
    store: &MemoryStore,
    user_id: Uuid,
    account_id: Uuid,
    allow_last: bool,
) -> Result<AccountDeleteOutcome, AuthError> {
    let mut state = store.state.write().await;
    let Some(key) = state
        .oauth_accounts
        .iter()
        .find(|(_, account)| account.id == account_id && account.user_id == user_id)
        .map(|(key, _)| key.clone())
    else {
        return Ok(AccountDeleteOutcome::NotFound);
    };
    let count = state
        .oauth_accounts
        .values()
        .filter(|account| account.user_id == user_id)
        .count();
    if count == 1 && !allow_last {
        return Ok(AccountDeleteOutcome::LastAccount);
    }
    let removed = state
        .oauth_accounts
        .remove(&key)
        .expect("account key was found");
    if removed.provider_id == "credential" {
        state.passwords.remove(&user_id);
    }
    Ok(AccountDeleteOutcome::Deleted)
}

pub(super) async fn compare_and_swap_tokens(
    store: &MemoryStore,
    account: OAuthAccount,
    expected_refresh_token: Option<&str>,
    expected_updated_at: DateTime<Utc>,
) -> Result<OAuthTokenUpdateOutcome, AuthError> {
    let mut state = store.state.write().await;
    let key = (account.issuer.clone(), account.account_id.clone());
    let Some(stored) = state.oauth_accounts.get_mut(&key) else {
        return Ok(OAuthTokenUpdateOutcome::NotFound);
    };
    if stored.user_id != account.user_id {
        return Ok(OAuthTokenUpdateOutcome::NotFound);
    }
    if stored.updated_at != expected_updated_at
        || stored.refresh_token.as_deref() != expected_refresh_token
    {
        return Ok(OAuthTokenUpdateOutcome::Stale(stored.clone()));
    }
    *stored = account.clone();
    Ok(OAuthTokenUpdateOutcome::Updated(account))
}
