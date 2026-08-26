use super::{MemoryStore, phone_number};
use crate::store::DatabaseCreate;
use crate::{
    AccountDeleteOutcome, AuthError, AuthUser, OAuthAccount, OAuthAccountOwner,
    OAuthTokenUpdateOutcome,
};
use chrono::{DateTime, Utc};

#[cfg(test)]
mod create_tests;

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
        user: DatabaseCreate<AuthUser>,
        account: &dyn crate::store::DependentAccountPreparer,
    ) -> Result<crate::OAuthAccountOwner, AuthError> {
        create_user(self, user, account).await
    }
    async fn link_oauth_account(
        &self,
        account: DatabaseCreate<OAuthAccount>,
    ) -> Result<OAuthAccount, AuthError> {
        link(self, account).await
    }
    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError> {
        update_tokens(self, account).await
    }
    async fn list_user_accounts(&self, user_id: &str) -> Result<Vec<OAuthAccount>, AuthError> {
        list(self, user_id).await
    }
    async fn delete_user_account(
        &self,
        user_id: &str,
        account_id: &str,
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
    user: DatabaseCreate<AuthUser>,
    account_preparer: &dyn crate::store::DependentAccountPreparer,
) -> Result<OAuthAccountOwner, AuthError> {
    let (user, account, reserved_username, reserved_account_key) =
        prepare_oauth_create(store, user, account_preparer).await?;
    let key = (
        account.record.issuer.clone(),
        account.record.account_id.clone(),
    );
    let mut state = store.state.write().await;
    release_pending_create_locked(
        &mut state,
        reserved_username.as_deref(),
        &user.email,
        reserved_account_key.as_ref(),
    );
    if state.oauth_accounts.contains_key(&key)
        || state.pending_oauth_accounts.contains(&key)
        || state.emails.contains_key(&user.email)
        || state.pending_emails.contains(&user.email)
        || user.username.as_ref().is_some_and(|username| {
            state.usernames.contains_key(username) || state.pending_usernames.contains(username)
        })
    {
        return Err(AuthError::UserAlreadyExists);
    }
    if phone_number::user_phone_number(&user)?.is_some_and(|phone_number| {
        !phone_number::phone_number_available(&state, phone_number, None)
    }) {
        return Err(AuthError::UserAlreadyExists);
    }
    let (mut account, account_id) = account.into_parts(store)?;
    account.id = store.create_id("account", account_id, state.oauth_accounts.len())?;
    account.user_id = user.id.clone();
    if let Some(username) = &user.username {
        state.usernames.insert(username.clone(), user.id.clone());
    }
    state.emails.insert(user.email.clone(), user.id.clone());
    phone_number::index_phone_number(&mut state, &user)?;
    state.users.insert(user.id.clone(), user.clone());
    state.oauth_accounts.insert(key, account.clone());
    Ok(OAuthAccountOwner { account, user })
}

type PreparedOAuthCreate = (
    AuthUser,
    DatabaseCreate<OAuthAccount>,
    Option<String>,
    Option<(String, String)>,
);

async fn prepare_oauth_create(
    store: &MemoryStore,
    user: DatabaseCreate<AuthUser>,
    account_preparer: &dyn crate::store::DependentAccountPreparer,
) -> Result<PreparedOAuthCreate, AuthError> {
    let (mut user, user_id) = user.into_parts(store)?;
    user.email = user.email.to_lowercase();
    let mut state = store.state.write().await;
    user.id = store.create_id(
        "user",
        user_id,
        state.users.len() + state.pending_emails.len(),
    )?;
    if state.emails.contains_key(&user.email) || state.pending_emails.contains(&user.email) {
        return Err(AuthError::UserAlreadyExists);
    }
    if user.username.as_ref().is_some_and(|username| {
        state.usernames.contains_key(username) || state.pending_usernames.contains(username)
    }) {
        return Err(AuthError::UserAlreadyExists);
    }
    if phone_number::user_phone_number(&user)?.is_some_and(|phone_number| {
        !phone_number::phone_number_available(&state, phone_number, None)
    }) {
        return Err(AuthError::UserAlreadyExists);
    }
    let reserved_username = user.username.clone();
    let reserved_account_key = account_preparer.pending_account_key(&user);
    if reserved_account_key.as_ref().is_some_and(|key| {
        state.oauth_accounts.contains_key(key) || state.pending_oauth_accounts.contains(key)
    }) {
        return Err(AuthError::UserAlreadyExists);
    }
    state.pending_emails.insert(user.email.clone());
    if let Some(username) = &reserved_username {
        state.pending_usernames.insert(username.clone());
    }
    if let Some(key) = &reserved_account_key {
        state.pending_oauth_accounts.insert(key.clone());
    }
    drop(state);
    let prepared = account_preparer
        .prepare_account(crate::DependentAccountContext {
            user: &user,
            user_operation: crate::DatabaseWriteOperation::Create,
            existing_account: None,
        })
        .await;
    let account = match prepared {
        Ok(crate::DatabaseWrite::Create(account)) => account,
        Ok(crate::DatabaseWrite::Update(_)) => {
            release_pending_create(
                store,
                reserved_username.as_deref(),
                &user.email,
                reserved_account_key.as_ref(),
            )
            .await;
            return Err(AuthError::Storage(
                "fresh OAuth user preparer returned an account update".into(),
            ));
        }
        Err(error) => {
            release_pending_create(
                store,
                reserved_username.as_deref(),
                &user.email,
                reserved_account_key.as_ref(),
            )
            .await;
            return Err(error);
        }
    };
    Ok((user, account, reserved_username, reserved_account_key))
}

async fn release_pending_create(
    store: &MemoryStore,
    username: Option<&str>,
    email: &str,
    account_key: Option<&(String, String)>,
) {
    let mut state = store.state.write().await;
    release_pending_create_locked(&mut state, username, email, account_key);
}

fn release_pending_create_locked(
    state: &mut super::MemoryState,
    username: Option<&str>,
    email: &str,
    account_key: Option<&(String, String)>,
) {
    if let Some(username) = username {
        state.pending_usernames.remove(username);
    }
    state.pending_emails.remove(email);
    if let Some(key) = account_key {
        state.pending_oauth_accounts.remove(key);
    }
}

pub(super) async fn link(
    store: &MemoryStore,
    account: DatabaseCreate<OAuthAccount>,
) -> Result<OAuthAccount, AuthError> {
    let (mut account, id) = account.into_parts(store)?;
    let mut state = store.state.write().await;
    account.id = store.create_id("account", id, state.oauth_accounts.len())?;
    if !state.users.contains_key(&account.user_id) {
        return Err(AuthError::NotFound);
    }
    let key = (account.issuer.clone(), account.account_id.clone());
    if state.oauth_accounts.contains_key(&key) || state.pending_oauth_accounts.contains(&key) {
        return Err(AuthError::UserAlreadyExists);
    }
    if account.provider_id == "credential"
        && let Some(password) = &account.password
    {
        state
            .passwords
            .insert(account.user_id.clone(), password.clone());
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
    if state.pending_oauth_accounts.contains(&key) {
        return Err(AuthError::UserAlreadyExists);
    }
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
    user_id: &str,
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
    accounts.sort_by_key(|account| (account.created_at, account.id.clone()));
    Ok(accounts)
}

pub(super) async fn delete(
    store: &MemoryStore,
    user_id: &str,
    account_id: &str,
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
        state.passwords.remove(user_id);
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
