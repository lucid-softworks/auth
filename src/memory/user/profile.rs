use super::{MemoryStore, ensure_phone_number_available, phone_number};
use crate::store::DatabaseCreate;
use crate::{AuthError, AuthUser, UserProfileUpdate, UsernameError};
use chrono::{DateTime, Utc};

pub(in crate::memory) async fn create_without_account(
    store: &MemoryStore,
    user: DatabaseCreate<AuthUser>,
) -> Result<AuthUser, AuthError> {
    let (mut user, id) = user.into_parts(store)?;
    user.email = user.email.to_lowercase();
    let mut state = store.state.write().await;
    user.id = store.create_id("user", id, state.users.len() + state.pending_emails.len())?;
    if state.emails.contains_key(&user.email) || state.pending_emails.contains(&user.email) {
        return Err(AuthError::UserAlreadyExists);
    }
    ensure_phone_number_available(&state, &user, None)?;
    if let Some(username) = &user.username {
        if state.usernames.contains_key(username) || state.pending_usernames.contains(username) {
            return Err(UsernameError::AlreadyTaken.into());
        }
        state.usernames.insert(username.clone(), user.id.clone());
    }
    state.emails.insert(user.email.clone(), user.id.clone());
    phone_number::index_phone_number(&mut state, &user)?;
    state.users.insert(user.id.clone(), user.clone());
    Ok(user)
}

pub(in crate::memory) async fn find_by_username(
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

pub(in crate::memory) async fn find_by_email(
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

pub(in crate::memory) async fn update_profile(
    store: &MemoryStore,
    user_id: &str,
    update: UserProfileUpdate,
) -> Result<Option<AuthUser>, AuthError> {
    let mut state = store.state.write().await;
    let Some(current) = state.users.get(user_id) else {
        return Ok(None);
    };
    if let Some(username) = &update.username
        && (state
            .usernames
            .get(username)
            .is_some_and(|owner| owner != user_id)
            || state.pending_usernames.contains(username))
    {
        return Err(UsernameError::AlreadyTaken.into());
    }
    let previous_username = current.username.clone();
    let previous_phone_number = phone_number::user_phone_number(current)?.map(str::to_owned);
    let next_phone_number = match update.additional_fields.get("phoneNumber") {
        Some(_) => {
            phone_number::phone_number_from_fields(&update.additional_fields)?.map(str::to_owned)
        }
        None => previous_phone_number.clone(),
    };
    if next_phone_number.as_deref().is_some_and(|phone_number| {
        !phone_number::phone_number_available(&state, phone_number, Some(user_id))
    }) {
        return Err(AuthError::UserAlreadyExists);
    }
    let user = state.users.get_mut(user_id).expect("user checked above");
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
    user.additional_fields.extend(update.additional_fields);
    user.updated_at = Utc::now();
    let updated = user.clone();
    if previous_username != updated.username {
        if let Some(previous) = previous_username {
            state.usernames.remove(&previous);
        }
        if let Some(username) = &updated.username {
            state.usernames.insert(username.clone(), user_id.to_owned());
        }
    }
    phone_number::replace_phone_number_index(
        &mut state,
        user_id,
        previous_phone_number,
        next_phone_number,
    );
    Ok(Some(updated))
}

pub(in crate::memory) async fn update_email(
    store: &MemoryStore,
    user_id: &str,
    expected_email: &str,
    new_email: &str,
    email_verified: bool,
) -> Result<Option<AuthUser>, AuthError> {
    let expected_email = expected_email.to_lowercase();
    let new_email = new_email.to_lowercase();
    let mut state = store.state.write().await;
    if state
        .emails
        .get(&new_email)
        .is_some_and(|owner| owner != user_id)
        || state.pending_emails.contains(&new_email)
    {
        return Err(AuthError::UserAlreadyExistsEmail);
    }
    let Some(user) = state
        .users
        .get_mut(user_id)
        .filter(|user| user.email == expected_email)
    else {
        return Ok(None);
    };
    user.email = new_email.clone();
    user.email_verified = email_verified;
    user.updated_at = Utc::now();
    let updated = user.clone();
    state.emails.remove(&expected_email);
    state.emails.insert(new_email, user_id.to_owned());
    Ok(Some(updated))
}

pub(in crate::memory) async fn find_by_id(
    store: &MemoryStore,
    user_id: &str,
) -> Result<Option<AuthUser>, AuthError> {
    Ok(store.state.read().await.users.get(user_id).cloned())
}

pub(in crate::memory) async fn promote_email_owner(
    store: &MemoryStore,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AuthUser>, AuthError> {
    let mut state = store.state.write().await;
    let Some(user) = state.users.get(user_id) else {
        return Ok(None);
    };
    if user.email_verified {
        return Ok(Some(user.clone()));
    }
    state.passwords.remove(user_id);
    state
        .oauth_accounts
        .retain(|_, account| account.user_id != user_id || account.provider_id != "credential");
    state
        .sessions
        .retain(|_, session| session.user_id != user_id);
    let user = state
        .users
        .get_mut(user_id)
        .ok_or_else(|| AuthError::Storage("user disappeared during promotion".into()))?;
    user.email_verified = true;
    user.updated_at = now;
    Ok(Some(user.clone()))
}
