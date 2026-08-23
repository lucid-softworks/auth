use super::MemoryStore;
use crate::{AuthError, AuthUser, OAuthAccount, OAuthAccountOwner};

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
    account.user_id = user.id;
    state.emails.insert(user.email.clone(), user.id);
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
