use crate::{
    ApiKey, AuthError, AuthSession, AuthStore, AuthUser, EmailVerificationOutcome, GuestGrant,
    PasskeyDeleteOutcome, PasswordResetOutcome, StoredPasskey, VerificationValue,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;

mod access;
mod api_key;
mod guest_capability;
mod operator_security;
mod security;
mod user;
mod verification;

#[derive(Default)]
struct MemoryState {
    users: HashMap<Uuid, AuthUser>,
    usernames: HashMap<String, Uuid>,
    emails: HashMap<String, Uuid>,
    passwords: HashMap<Uuid, String>,
    sessions: HashMap<String, AuthSession>,
    passkeys: HashMap<Uuid, StoredPasskey>,
    guest_grants: HashMap<Uuid, GuestGrant>,
    guest_sessions: HashMap<Uuid, Uuid>,
    api_keys: HashMap<Uuid, ApiKey>,
    rate_limits: HashMap<String, RateLimitWindow>,
    temporary_passwords: HashSet<Uuid>,
    verifications: HashMap<(String, String), VerificationValue>,
}

struct RateLimitWindow {
    attempts: usize,
    expires_at: DateTime<Utc>,
}

/// In-memory adapter for tests and explicitly non-persistent development use.
#[derive(Clone, Default)]
pub struct MemoryStore {
    state: Arc<RwLock<MemoryState>>,
}

#[async_trait]
impl AuthStore for MemoryStore {
    async fn create_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        user::create_password(self, user, password_hash).await
    }

    async fn upsert_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        user::upsert_password(self, user, password_hash).await
    }

    async fn create_anonymous_user(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        user::create_without_account(self, user).await
    }

    async fn create_user_without_account(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        user::create_without_account(self, user).await
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError> {
        user::find_by_username(self, username).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        user::find_by_email(self, email).await
    }

    async fn update_user_profile(
        &self,
        user_id: Uuid,
        update: crate::UserProfileUpdate,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::update_profile(self, user_id, update).await
    }

    async fn update_user_email(
        &self,
        user_id: Uuid,
        expected_email: &str,
        new_email: &str,
        email_verified: bool,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::update_email(self, user_id, expected_email, new_email, email_verified).await
    }

    async fn consume_email_verification(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<EmailVerificationOutcome, AuthError> {
        let mut state = self.state.write().await;
        let key = ("email-verification".to_owned(), token_hash.to_owned());
        let Some(value) = state.verifications.remove(&key) else {
            return Ok(EmailVerificationOutcome::InvalidToken);
        };
        if value.expires_at <= now {
            return Ok(EmailVerificationOutcome::Expired);
        }
        let Some(email) = value
            .payload
            .get("email")
            .and_then(serde_json::Value::as_str)
        else {
            return Err(AuthError::Storage(
                "email verification payload is invalid".into(),
            ));
        };
        let Some(user_id) = state.emails.get(email).copied() else {
            return Ok(EmailVerificationOutcome::UserNotFound);
        };
        let user = state
            .users
            .get_mut(&user_id)
            .ok_or_else(|| AuthError::Storage("email index is inconsistent".into()))?;
        if user.email_verified {
            return Ok(EmailVerificationOutcome::AlreadyVerified(user.clone()));
        }
        user.email_verified = true;
        user.updated_at = now;
        Ok(EmailVerificationOutcome::Verified(user.clone()))
    }

    async fn consume_password_reset(
        &self,
        token_hash: &str,
        password_hash: String,
        now: DateTime<Utc>,
        revoke_sessions: bool,
    ) -> Result<PasswordResetOutcome, AuthError> {
        let mut state = self.state.write().await;
        let key = ("password-reset".to_owned(), token_hash.to_owned());
        let Some(value) = state.verifications.remove(&key) else {
            return Ok(PasswordResetOutcome::InvalidToken);
        };
        if value.expires_at <= now {
            return Ok(PasswordResetOutcome::InvalidToken);
        }
        let Some(user_id) = value
            .payload
            .get("user_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return Err(AuthError::Storage(
                "password reset payload is invalid".into(),
            ));
        };
        if !state.users.contains_key(&user_id) {
            return Ok(PasswordResetOutcome::UserNotFound);
        }
        state.passwords.insert(user_id, password_hash);
        if revoke_sessions {
            state
                .sessions
                .retain(|_, session| session.user_id != user_id);
        }
        let user = state
            .users
            .get_mut(&user_id)
            .ok_or_else(|| AuthError::Storage("email index is inconsistent".into()))?;
        user.updated_at = now;
        Ok(PasswordResetOutcome::Reset(Box::new(user.clone())))
    }

    async fn promote_email_owner(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::promote_email_owner(self, user_id, now).await
    }

    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        user::find_password_hash(self, user_id).await
    }

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError> {
        user::update_password_hash(self, user_id, password_hash).await
    }

    async fn set_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError> {
        user::set_password_hash(self, user_id, password_hash).await
    }

    async fn save_passkey(&self, passkey: StoredPasskey) -> Result<StoredPasskey, AuthError> {
        let mut state = self.state.write().await;
        if state
            .passkeys
            .values()
            .any(|stored| stored.credential_id == passkey.credential_id)
        {
            return Err(AuthError::CredentialAlreadyRegistered);
        }
        state.passkeys.insert(passkey.id, passkey.clone());
        Ok(passkey)
    }

    async fn list_passkeys(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .passkeys
            .values()
            .filter(|passkey| passkey.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .passkeys
            .values()
            .find(|passkey| passkey.credential_id == credential_id)
            .cloned())
    }

    async fn find_passkey_by_id(
        &self,
        passkey_id: Uuid,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        Ok(self.state.read().await.passkeys.get(&passkey_id).cloned())
    }

    async fn update_passkey_after_authentication(
        &self,
        passkey: StoredPasskey,
        expected_counter: u32,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let Some(current) = state.passkeys.get(&passkey.id) else {
            return Ok(false);
        };
        if current.counter != expected_counter {
            return Ok(false);
        }
        state.passkeys.insert(passkey.id, passkey);
        Ok(true)
    }

    async fn update_passkey_name(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        let mut state = self.state.write().await;
        let Some(passkey) = state
            .passkeys
            .get_mut(&passkey_id)
            .filter(|passkey| passkey.user_id == user_id)
        else {
            return Ok(None);
        };
        passkey.name = Some(name);
        passkey.updated_at = Utc::now();
        Ok(Some(passkey.clone()))
    }

    async fn delete_passkey(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        minimum_remaining: usize,
    ) -> Result<PasskeyDeleteOutcome, AuthError> {
        let mut state = self.state.write().await;
        let owned = state
            .passkeys
            .get(&passkey_id)
            .is_some_and(|passkey| passkey.user_id == user_id);
        if !owned {
            return Ok(PasskeyDeleteOutcome::NotFound);
        }
        let count = state
            .passkeys
            .values()
            .filter(|passkey| passkey.user_id == user_id)
            .count();
        if count <= minimum_remaining {
            return Ok(PasskeyDeleteOutcome::MinimumRequired);
        }
        state.passkeys.remove(&passkey_id);
        let remaining = count - 1;
        Ok(PasskeyDeleteOutcome::Deleted { remaining })
    }

    async fn delete_user_passkeys(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .passkeys
            .retain(|_, passkey| passkey.user_id != user_id);
        Ok(())
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<AuthUser>, AuthError> {
        user::find_by_id(self, user_id).await
    }

    async fn create_session(&self, session: AuthSession) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .sessions
            .insert(session.token_hash.clone(), session);
        Ok(())
    }

    async fn find_session(
        &self,
        token_hash: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
        let state = self.state.read().await;
        let Some(session) = state.sessions.get(token_hash).cloned() else {
            return Ok(None);
        };
        Ok(state
            .users
            .get(&session.user_id)
            .cloned()
            .map(|user| (session, user)))
    }

    async fn update_session_fields(
        &self,
        session_id: Uuid,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<AuthSession>, AuthError> {
        let mut state = self.state.write().await;
        let Some(session) = state
            .sessions
            .values_mut()
            .find(|session| session.id == session_id)
        else {
            return Ok(None);
        };
        session.additional_fields.extend(fields);
        session.updated_at = Utc::now();
        Ok(Some(session.clone()))
    }

    async fn delete_session(&self, token_hash: &str) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        if let Some(session) = state.sessions.remove(token_hash) {
            state.guest_sessions.remove(&session.id);
        }
        Ok(())
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        state.sessions.retain(|_, session| session.expires_at > now);
        let active_sessions: std::collections::HashSet<_> =
            state.sessions.values().map(|session| session.id).collect();
        state
            .guest_sessions
            .retain(|session_id, _| active_sessions.contains(session_id));
        Ok(())
    }
}
