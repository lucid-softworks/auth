use super::{MemoryStore, phone_number};
use crate::store::{DatabaseCreate, DatabaseWrite};
use crate::{AuthError, AuthUser, OAuthAccount, OAuthAccountOwner, UsernameError};
use chrono::Utc;

mod credentials;
mod profile;

pub(super) use credentials::{find_password_hash, set_password_hash, update_password_hash};
pub(super) use profile::{
    create_without_account, find_by_email, find_by_id, find_by_username, promote_email_owner,
    update_email, update_profile,
};

pub(super) async fn create_password(
    store: &MemoryStore,
    user: DatabaseCreate<AuthUser>,
    account: &dyn crate::store::DependentAccountPreparer,
) -> Result<OAuthAccountOwner, AuthError> {
    let (user, reserved_username, reserved_account_key) =
        reserve_password_create(store, user, account).await?;
    let (account, password_hash) = prepare_fresh_password_account(
        store,
        &user,
        account,
        reserved_username.as_deref(),
        &reserved_account_key,
    )
    .await?;
    let mut state = store.state.write().await;
    release_pending(
        &mut state,
        reserved_username.as_deref(),
        &user.email,
        &reserved_account_key,
    );
    if user
        .username
        .as_ref()
        .is_some_and(|username| state.usernames.contains_key(username))
    {
        return Err(UsernameError::AlreadyTaken.into());
    }
    if state.emails.contains_key(&user.email) || state.pending_emails.contains(&user.email) {
        return Err(AuthError::UserAlreadyExists);
    }
    ensure_phone_number_available(&state, &user, None)?;
    let account_key = (account.record.issuer.clone(), user.id.clone());
    if state.oauth_accounts.contains_key(&account_key)
        || state.pending_oauth_accounts.contains(&account_key)
    {
        return Err(AuthError::UserAlreadyExists);
    }
    let (mut account, account_id) = account.into_parts(store)?;
    account.id = store.create_id("account", account_id, state.oauth_accounts.len())?;
    account.user_id = user.id.clone();
    account.account_id = user.id.clone();
    if let Some(username) = &user.username {
        state.usernames.insert(username.clone(), user.id.clone());
    }
    state.emails.insert(user.email.clone(), user.id.clone());
    phone_number::index_phone_number(&mut state, &user)?;
    state.passwords.insert(user.id.clone(), password_hash);
    state.oauth_accounts.insert(account_key, account.clone());
    state.users.insert(user.id.clone(), user.clone());
    Ok(OAuthAccountOwner { account, user })
}

async fn reserve_password_create(
    store: &MemoryStore,
    user: DatabaseCreate<AuthUser>,
    account: &dyn crate::store::DependentAccountPreparer,
) -> Result<(AuthUser, Option<String>, (String, String)), AuthError> {
    let (mut user, user_id) = user.into_parts(store)?;
    user.email = user.email.to_lowercase();
    let mut state = store.state.write().await;
    user.id = store.create_id(
        "user",
        user_id,
        state.users.len() + state.pending_emails.len(),
    )?;
    if user.username.as_ref().is_some_and(|username| {
        state.usernames.contains_key(username) || state.pending_usernames.contains(username)
    }) {
        return Err(UsernameError::AlreadyTaken.into());
    }
    if state.emails.contains_key(&user.email) || state.pending_emails.contains(&user.email) {
        return Err(AuthError::UserAlreadyExists);
    }
    ensure_phone_number_available(&state, &user, None)?;
    let reserved_username = user.username.clone();
    if let Some(username) = &reserved_username {
        state.pending_usernames.insert(username.clone());
    }
    state.pending_emails.insert(user.email.clone());
    let reserved_account_key = account
        .pending_account_key(&user)
        .unwrap_or_else(|| ("local:credential".to_owned(), user.id.clone()));
    if state.oauth_accounts.contains_key(&reserved_account_key)
        || !state
            .pending_oauth_accounts
            .insert(reserved_account_key.clone())
    {
        if let Some(username) = &reserved_username {
            state.pending_usernames.remove(username);
        }
        state.pending_emails.remove(&user.email);
        return Err(AuthError::UserAlreadyExists);
    }
    drop(state);
    Ok((user, reserved_username, reserved_account_key))
}

async fn prepare_fresh_password_account(
    store: &MemoryStore,
    user: &AuthUser,
    preparer: &dyn crate::store::DependentAccountPreparer,
    reserved_username: Option<&str>,
    reserved_account_key: &(String, String),
) -> Result<(DatabaseCreate<OAuthAccount>, String), AuthError> {
    let prepared = preparer
        .prepare_account(crate::DependentAccountContext {
            user,
            user_operation: crate::DatabaseWriteOperation::Create,
            existing_account: None,
        })
        .await;
    let account = match prepared {
        Ok(DatabaseWrite::Create(account)) => account,
        Ok(DatabaseWrite::Update(_)) => {
            release_pending_from_store(store, reserved_username, &user.email, reserved_account_key)
                .await;
            return Err(AuthError::Storage(
                "fresh password user preparer returned an account update".into(),
            ));
        }
        Err(error) => {
            release_pending_from_store(store, reserved_username, &user.email, reserved_account_key)
                .await;
            return Err(error);
        }
    };
    let Some(password_hash) = account.record.password.clone() else {
        release_pending_from_store(store, reserved_username, &user.email, reserved_account_key)
            .await;
        return Err(AuthError::Storage(
            "credential account requires a password hash".into(),
        ));
    };
    Ok((account, password_hash))
}

pub(super) async fn upsert_password(
    store: &MemoryStore,
    user: DatabaseWrite<AuthUser>,
    account: &dyn crate::DependentAccountPreparer,
) -> Result<crate::DatabaseAccountOwnerWrite, AuthError> {
    let (mut user, user_operation) = match user {
        DatabaseWrite::Create(value) => {
            let (record, id) = value.into_parts(store)?;
            let state = store.state.read().await;
            let mut record = record;
            record.id =
                store.create_id("user", id, state.users.len() + state.pending_emails.len())?;
            (record, crate::DatabaseWriteOperation::Create)
        }
        DatabaseWrite::Update(record) => (record, crate::DatabaseWriteOperation::Update),
    };
    user.email = user.email.to_lowercase();
    let username = user
        .username
        .as_deref()
        .ok_or_else(|| AuthError::Storage("password user requires a username".into()))?
        .to_owned();
    let mut state = store.state.write().await;
    let existing_id = state.usernames.get(&username).cloned();
    match user_operation {
        crate::DatabaseWriteOperation::Create if existing_id.is_some() => {
            return Err(UsernameError::AlreadyTaken.into());
        }
        crate::DatabaseWriteOperation::Update
            if existing_id.as_deref() != Some(user.id.as_str())
                || !state.users.contains_key(&user.id) =>
        {
            return Err(AuthError::NotFound);
        }
        _ => {}
    }
    if state
        .emails
        .get(&user.email)
        .is_some_and(|owner| owner != &user.id)
    {
        return Err(AuthError::UserAlreadyExists);
    }
    ensure_phone_number_available(&state, &user, Some(&user.id))?;
    let key = account
        .pending_account_key(&user)
        .unwrap_or_else(|| ("local:credential".to_owned(), user.id.clone()));
    let existing_account = state.oauth_accounts.get(&key).cloned();
    if state.pending_usernames.contains(&username)
        || state.pending_emails.contains(&user.email)
        || state.pending_oauth_accounts.contains(&key)
    {
        return Err(AuthError::UserAlreadyExists);
    }
    state.pending_usernames.insert(username.clone());
    state.pending_emails.insert(user.email.clone());
    state.pending_oauth_accounts.insert(key.clone());
    drop(state);

    let prepared = account
        .prepare_account(crate::DependentAccountContext {
            user: &user,
            user_operation,
            existing_account: existing_account.as_ref(),
        })
        .await;
    let account = match prepared {
        Ok(account) => account,
        Err(error) => {
            let mut state = store.state.write().await;
            state.pending_usernames.remove(&username);
            state.pending_emails.remove(&user.email);
            state.pending_oauth_accounts.remove(&key);
            return Err(error);
        }
    };
    commit_password_upsert(store, user, username, key, account, user_operation).await
}

async fn commit_password_upsert(
    store: &MemoryStore,
    user: AuthUser,
    username: String,
    key: (String, String),
    account: DatabaseWrite<OAuthAccount>,
    user_operation: crate::DatabaseWriteOperation,
) -> Result<crate::DatabaseAccountOwnerWrite, AuthError> {
    let mut state = store.state.write().await;
    release_pending(&mut state, Some(&username), &user.email, &key);
    match user_operation {
        crate::DatabaseWriteOperation::Create => {
            if state.usernames.contains_key(&username) || state.emails.contains_key(&user.email) {
                return Err(AuthError::UserAlreadyExists);
            }
        }
        crate::DatabaseWriteOperation::Update => {
            if state.usernames.get(&username).map(String::as_str) != Some(user.id.as_str())
                || !state.users.contains_key(&user.id)
                || state
                    .emails
                    .get(&user.email)
                    .is_some_and(|owner| owner != &user.id)
            {
                return Err(AuthError::UserAlreadyExists);
            }
        }
    }
    let (mut account, account_operation, password_hash) =
        materialize_password_account(store, &state, &user, &key, account)?;
    let stored = match user_operation {
        crate::DatabaseWriteOperation::Create => {
            if state.usernames.contains_key(&username) || state.emails.contains_key(&user.email) {
                return Err(AuthError::UserAlreadyExists);
            }
            state.usernames.insert(username, user.id.clone());
            state.emails.insert(user.email.clone(), user.id.clone());
            phone_number::index_phone_number(&mut state, &user)?;
            state.users.insert(user.id.clone(), user.clone());
            user
        }
        crate::DatabaseWriteOperation::Update => {
            update_existing(&mut state, &user.id.clone(), user)?
        }
    };
    state.passwords.insert(stored.id.clone(), password_hash);
    account.updated_at = Utc::now();
    state.oauth_accounts.insert(key, account.clone());
    Ok(crate::DatabaseAccountOwnerWrite {
        owner: OAuthAccountOwner {
            account,
            user: stored,
        },
        user_operation,
        account_operation,
    })
}

fn materialize_password_account(
    store: &MemoryStore,
    state: &super::MemoryState,
    user: &AuthUser,
    key: &(String, String),
    account: DatabaseWrite<OAuthAccount>,
) -> Result<(OAuthAccount, crate::DatabaseWriteOperation, String), AuthError> {
    let (mut account, operation) = match account {
        DatabaseWrite::Create(value) => {
            if state.oauth_accounts.contains_key(key) {
                return Err(AuthError::UserAlreadyExists);
            }
            let (mut record, id) = value.into_parts(store)?;
            record.id = store.create_id("account", id, state.oauth_accounts.len())?;
            (record, crate::DatabaseWriteOperation::Create)
        }
        DatabaseWrite::Update(record) => {
            let existing = state
                .oauth_accounts
                .get(key)
                .ok_or(AuthError::CredentialAccountNotFound)?;
            if existing.id != record.id {
                return Err(AuthError::Storage(
                    "credential account update changed its database ID".into(),
                ));
            }
            (record, crate::DatabaseWriteOperation::Update)
        }
    };
    account.user_id = user.id.clone();
    account.account_id = user.id.clone();
    let password_hash = account
        .password
        .clone()
        .ok_or_else(|| AuthError::Storage("credential account requires a password hash".into()))?;
    Ok((account, operation, password_hash))
}

fn release_pending(
    state: &mut super::MemoryState,
    username: Option<&str>,
    email: &str,
    account_key: &(String, String),
) {
    if let Some(username) = username {
        state.pending_usernames.remove(username);
    }
    state.pending_emails.remove(email);
    state.pending_oauth_accounts.remove(account_key);
}

async fn release_pending_from_store(
    store: &MemoryStore,
    username: Option<&str>,
    email: &str,
    account_key: &(String, String),
) {
    let mut state = store.state.write().await;
    release_pending(&mut state, username, email, account_key);
}

fn update_existing(
    state: &mut super::MemoryState,
    id: &str,
    user: AuthUser,
) -> Result<AuthUser, AuthError> {
    let previous_email = state
        .users
        .get(id)
        .ok_or_else(|| AuthError::Storage("username index is inconsistent".into()))?
        .email
        .clone();
    let previous_phone_number = phone_number::user_phone_number(
        state
            .users
            .get(id)
            .ok_or_else(|| AuthError::Storage("username index is inconsistent".into()))?,
    )?
    .map(str::to_owned);
    let existing = state
        .users
        .get_mut(id)
        .ok_or_else(|| AuthError::Storage("username index is inconsistent".into()))?;
    existing.name = user.name;
    existing.email = user.email;
    existing.role = user.role;
    existing.additional_fields = user.additional_fields;
    existing.updated_at = user.updated_at;
    let stored = existing.clone();
    state.emails.remove(&previous_email);
    state.emails.insert(stored.email.clone(), id.to_owned());
    let current_phone_number = phone_number::user_phone_number(&stored)?.map(str::to_owned);
    phone_number::replace_phone_number_index(
        state,
        id,
        previous_phone_number,
        current_phone_number,
    );
    Ok(stored)
}

pub(super) fn ensure_phone_number_available(
    state: &super::MemoryState,
    user: &AuthUser,
    owner: Option<&str>,
) -> Result<(), AuthError> {
    if phone_number::user_phone_number(user)?.is_some_and(|phone_number| {
        !phone_number::phone_number_available(state, phone_number, owner)
    }) {
        return Err(AuthError::UserAlreadyExists);
    }
    Ok(())
}

#[cfg(test)]
mod create_tests;
