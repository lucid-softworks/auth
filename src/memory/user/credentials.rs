use super::*;

pub(in crate::memory) async fn find_password_hash(
    store: &MemoryStore,
    user_id: &str,
) -> Result<Option<String>, AuthError> {
    Ok(store.state.read().await.passwords.get(user_id).cloned())
}

pub(in crate::memory) async fn update_password_hash(
    store: &MemoryStore,
    user_id: &str,
    password_hash: String,
) -> Result<(), AuthError> {
    let mut state = store.state.write().await;
    let stored = state
        .passwords
        .get_mut(user_id)
        .ok_or(AuthError::CredentialAccountNotFound)?;
    *stored = password_hash.clone();
    let now = Utc::now();
    if let Some(account) = state
        .oauth_accounts
        .values_mut()
        .find(|account| account.user_id == user_id && account.provider_id == "credential")
    {
        account.password = Some(password_hash);
        account.updated_at = now;
    }
    if let Some(user) = state.users.get_mut(user_id) {
        user.updated_at = now;
    }
    Ok(())
}

pub(in crate::memory) async fn set_password_hash(
    store: &MemoryStore,
    account_id: &dyn crate::store::DatabaseIdSupplier,
    user_id: &str,
    password_hash: String,
) -> Result<(), AuthError> {
    let mut state = store.state.write().await;
    if !state.users.contains_key(user_id) {
        return Err(AuthError::NotFound);
    }
    state
        .passwords
        .insert(user_id.to_owned(), password_hash.clone());
    let user = state
        .users
        .get(user_id)
        .expect("user checked above")
        .clone();
    let key = ("local:credential".to_owned(), user_id.to_owned());
    if let Some(account) = state.oauth_accounts.get_mut(&key) {
        account.password = Some(password_hash);
        account.updated_at = Utc::now();
    } else {
        let mut account = credential_account(&user, password_hash);
        account.id =
            store.create_id("account", account_id.prepare()?, state.oauth_accounts.len())?;
        state.oauth_accounts.insert(key, account);
    }
    if let Some(user) = state.users.get_mut(user_id) {
        user.updated_at = Utc::now();
    }
    Ok(())
}

fn credential_account(user: &AuthUser, password: String) -> OAuthAccount {
    OAuthAccount {
        // Replaced from the lazy ID supplier before this draft is persisted.
        id: String::new(),
        user_id: user.id.clone(),
        issuer: "local:credential".into(),
        account_id: user.id.clone(),
        provider_id: "credential".into(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: Some(password),
        additional_fields: serde_json::Map::new(),
        created_at: user.created_at,
        updated_at: Utc::now(),
    }
}
