use super::MemoryStore;
use crate::{AuthError, AuthUser, UserProfileUpdate, UsernameError};
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub(super) async fn create_password(
    store: &MemoryStore,
    mut user: AuthUser,
    password_hash: String,
) -> Result<AuthUser, AuthError> {
    user.email = user.email.to_lowercase();
    let mut state = store.state.write().await;
    if user
        .username
        .as_ref()
        .is_some_and(|username| state.usernames.contains_key(username))
    {
        return Err(UsernameError::AlreadyTaken.into());
    }
    if state.emails.contains_key(&user.email) {
        return Err(AuthError::UserAlreadyExists);
    }
    if let Some(username) = &user.username {
        state.usernames.insert(username.clone(), user.id);
    }
    state.emails.insert(user.email.clone(), user.id);
    state.passwords.insert(user.id, password_hash);
    state.users.insert(user.id, user.clone());
    Ok(user)
}

pub(super) async fn upsert_password(
    store: &MemoryStore,
    mut user: AuthUser,
    password_hash: String,
) -> Result<AuthUser, AuthError> {
    user.email = user.email.to_lowercase();
    let username = user
        .username
        .as_deref()
        .ok_or_else(|| AuthError::Storage("password user requires a username".into()))?
        .to_owned();
    let mut state = store.state.write().await;
    let existing_id = state.usernames.get(&username).copied();
    if state
        .emails
        .get(&user.email)
        .is_some_and(|owner| Some(*owner) != existing_id)
    {
        return Err(AuthError::UserAlreadyExists);
    }
    let stored = if let Some(id) = existing_id {
        update_existing(&mut state, id, user)?
    } else {
        state.usernames.insert(username, user.id);
        state.emails.insert(user.email.clone(), user.id);
        state.users.insert(user.id, user.clone());
        user
    };
    state.passwords.entry(stored.id).or_insert(password_hash);
    Ok(stored)
}

fn update_existing(
    state: &mut super::MemoryState,
    id: Uuid,
    user: AuthUser,
) -> Result<AuthUser, AuthError> {
    let previous_email = state
        .users
        .get(&id)
        .ok_or_else(|| AuthError::Storage("username index is inconsistent".into()))?
        .email
        .clone();
    let existing = state
        .users
        .get_mut(&id)
        .ok_or_else(|| AuthError::Storage("username index is inconsistent".into()))?;
    existing.name = user.name;
    existing.email = user.email;
    existing.role = user.role;
    existing.updated_at = user.updated_at;
    let stored = existing.clone();
    state.emails.remove(&previous_email);
    state.emails.insert(stored.email.clone(), id);
    Ok(stored)
}

pub(super) async fn create_without_account(
    store: &MemoryStore,
    mut user: AuthUser,
) -> Result<AuthUser, AuthError> {
    user.email = user.email.to_lowercase();
    let mut state = store.state.write().await;
    if state.emails.contains_key(&user.email) {
        return Err(AuthError::UserAlreadyExists);
    }
    if let Some(username) = &user.username {
        if state.usernames.contains_key(username) {
            return Err(AuthError::UserAlreadyExists);
        }
        state.usernames.insert(username.clone(), user.id);
    }
    state.emails.insert(user.email.clone(), user.id);
    state.users.insert(user.id, user.clone());
    Ok(user)
}

pub(super) async fn find_by_username(
    store: &MemoryStore,
    username: &str,
) -> Result<Option<AuthUser>, AuthError> {
    let state = store.state.read().await;
    Ok(state
        .usernames
        .get(username)
        .and_then(|id| state.users.get(id))
        .cloned())
}

pub(super) async fn find_by_email(
    store: &MemoryStore,
    email: &str,
) -> Result<Option<AuthUser>, AuthError> {
    let state = store.state.read().await;
    Ok(state
        .emails
        .get(&email.to_lowercase())
        .and_then(|id| state.users.get(id))
        .cloned())
}

pub(super) async fn update_profile(
    store: &MemoryStore,
    user_id: Uuid,
    update: UserProfileUpdate,
) -> Result<Option<AuthUser>, AuthError> {
    let mut state = store.state.write().await;
    let Some(current) = state.users.get(&user_id) else {
        return Ok(None);
    };
    if let Some(username) = &update.username
        && state
            .usernames
            .get(username)
            .is_some_and(|owner| *owner != user_id)
    {
        return Err(UsernameError::AlreadyTaken.into());
    }
    let previous_username = current.username.clone();
    let user = state.users.get_mut(&user_id).expect("user checked above");
    if let Some(name) = update.name {
        user.name = name;
    }
    if let Some(image) = update.image {
        user.image = image;
    }
    if let Some(username) = update.username {
        user.username = Some(username);
    }
    if let Some(display_username) = update.display_username {
        user.display_username = Some(display_username);
    }
    user.updated_at = Utc::now();
    let updated = user.clone();
    if previous_username != updated.username {
        if let Some(previous) = previous_username {
            state.usernames.remove(&previous);
        }
        if let Some(username) = &updated.username {
            state.usernames.insert(username.clone(), user_id);
        }
    }
    Ok(Some(updated))
}

pub(super) async fn find_by_id(
    store: &MemoryStore,
    user_id: Uuid,
) -> Result<Option<AuthUser>, AuthError> {
    Ok(store.state.read().await.users.get(&user_id).cloned())
}

pub(super) async fn promote_email_owner(
    store: &MemoryStore,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<AuthUser>, AuthError> {
    let mut state = store.state.write().await;
    let Some(user) = state.users.get(&user_id) else {
        return Ok(None);
    };
    if user.email_verified {
        return Ok(Some(user.clone()));
    }
    state.passwords.remove(&user_id);
    state
        .sessions
        .retain(|_, session| session.user_id != user_id);
    let user = state
        .users
        .get_mut(&user_id)
        .ok_or_else(|| AuthError::Storage("user disappeared during promotion".into()))?;
    user.email_verified = true;
    user.updated_at = now;
    Ok(Some(user.clone()))
}

pub(super) async fn find_password_hash(
    store: &MemoryStore,
    user_id: Uuid,
) -> Result<Option<String>, AuthError> {
    Ok(store.state.read().await.passwords.get(&user_id).cloned())
}

pub(super) async fn update_password_hash(
    store: &MemoryStore,
    user_id: Uuid,
    password_hash: String,
) -> Result<(), AuthError> {
    let mut state = store.state.write().await;
    let stored = state
        .passwords
        .get_mut(&user_id)
        .ok_or(AuthError::CredentialAccountNotFound)?;
    *stored = password_hash;
    if let Some(user) = state.users.get_mut(&user_id) {
        user.updated_at = Utc::now();
    }
    Ok(())
}

pub(super) async fn set_password_hash(
    store: &MemoryStore,
    user_id: Uuid,
    password_hash: String,
) -> Result<(), AuthError> {
    let mut state = store.state.write().await;
    if !state.users.contains_key(&user_id) {
        return Err(AuthError::NotFound);
    }
    state.passwords.insert(user_id, password_hash);
    if let Some(user) = state.users.get_mut(&user_id) {
        user.updated_at = Utc::now();
    }
    Ok(())
}
