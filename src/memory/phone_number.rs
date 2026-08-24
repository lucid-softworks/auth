use super::MemoryStore;
use crate::{
    AuthError, AuthUser,
    phone_number::{PhoneNumberStore, PhoneNumberWriteOutcome},
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value};
use uuid::Uuid;

const PHONE_NUMBER_FIELD: &str = "phoneNumber";
const PHONE_NUMBER_VERIFIED_FIELD: &str = "phoneNumberVerified";

#[async_trait]
impl PhoneNumberStore for MemoryStore {
    async fn find_user_by_phone_number(
        &self,
        phone_number: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        let state = self.state.read().await;
        let Some(user_id) = state.phone_numbers.get(phone_number) else {
            return Ok(None);
        };
        state.users.get(user_id).cloned().map(Some).ok_or_else(|| {
            AuthError::Storage("phone-number index references a missing user".into())
        })
    }

    async fn create_phone_number_user(
        &self,
        mut user: AuthUser,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError> {
        let phone_number = required_phone_number(&user)?.to_owned();
        user.email = user.email.to_lowercase();
        let mut state = self.state.write().await;
        if !phone_number_available(&state, &phone_number, None) {
            return Ok(PhoneNumberWriteOutcome::AlreadyExists);
        }
        if state.emails.contains_key(&user.email)
            || user
                .username
                .as_ref()
                .is_some_and(|username| state.usernames.contains_key(username))
        {
            return Err(AuthError::UserAlreadyExists);
        }
        if let Some(username) = &user.username {
            state.usernames.insert(username.clone(), user.id);
        }
        state.emails.insert(user.email.clone(), user.id);
        state.phone_numbers.insert(phone_number, user.id);
        state.users.insert(user.id, user.clone());
        Ok(PhoneNumberWriteOutcome::Written(user))
    }

    async fn update_user_phone_number(
        &self,
        user_id: Uuid,
        phone_number: Option<String>,
        verified: bool,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError> {
        let mut state = self.state.write().await;
        if phone_number.as_deref().is_some_and(|phone_number| {
            !phone_number_available(&state, phone_number, Some(user_id))
        }) {
            return Ok(PhoneNumberWriteOutcome::AlreadyExists);
        }
        let previous = state
            .users
            .get(&user_id)
            .map(user_phone_number)
            .transpose()?
            .flatten()
            .map(str::to_owned);
        let Some(user) = state.users.get_mut(&user_id) else {
            return Ok(PhoneNumberWriteOutcome::NotFound);
        };
        match &phone_number {
            Some(phone_number) => {
                user.additional_fields.insert(
                    PHONE_NUMBER_FIELD.to_owned(),
                    serde_json::Value::String(phone_number.clone()),
                );
            }
            None => {
                user.additional_fields.remove(PHONE_NUMBER_FIELD);
            }
        }
        user.additional_fields.insert(
            PHONE_NUMBER_VERIFIED_FIELD.to_owned(),
            serde_json::Value::Bool(verified),
        );
        user.updated_at = Utc::now();
        let user = user.clone();
        replace_phone_number_index(&mut state, user_id, previous, phone_number);
        Ok(PhoneNumberWriteOutcome::Written(user))
    }
}

fn required_phone_number(user: &AuthUser) -> Result<&str, AuthError> {
    user_phone_number(user)?
        .ok_or_else(|| AuthError::Storage("phone-number user requires a phone number".into()))
}

pub(super) fn user_phone_number(user: &AuthUser) -> Result<Option<&str>, AuthError> {
    phone_number_from_fields(&user.additional_fields)
}

pub(super) fn phone_number_from_fields(
    fields: &Map<String, Value>,
) -> Result<Option<&str>, AuthError> {
    match fields.get(PHONE_NUMBER_FIELD) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(phone_number)) => Ok(Some(phone_number)),
        Some(_) => Err(AuthError::Storage(
            "phoneNumber additional field must be a string or null".into(),
        )),
    }
}

pub(super) fn phone_number_available(
    state: &super::MemoryState,
    phone_number: &str,
    user_id: Option<Uuid>,
) -> bool {
    state
        .phone_numbers
        .get(phone_number)
        .is_none_or(|owner| Some(*owner) == user_id)
}

pub(super) fn index_phone_number(
    state: &mut super::MemoryState,
    user: &AuthUser,
) -> Result<(), AuthError> {
    if let Some(phone_number) = user_phone_number(user)? {
        state.phone_numbers.insert(phone_number.to_owned(), user.id);
    }
    Ok(())
}

pub(super) fn replace_phone_number_index(
    state: &mut super::MemoryState,
    user_id: Uuid,
    previous: Option<String>,
    current: Option<String>,
) {
    if previous == current {
        return;
    }
    if let Some(previous) = previous
        && state.phone_numbers.get(&previous) == Some(&user_id)
    {
        state.phone_numbers.remove(&previous);
    }
    if let Some(current) = current {
        state.phone_numbers.insert(current, user_id);
    }
}
