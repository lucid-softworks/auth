use super::{AuthService, hash_token, password::verify_password};
use crate::{
    AfterAuthEvent, AuthError, BeforeAuthEvent, DeleteAccountVerification, SessionWithUser,
    VerificationValue,
};
use chrono::Utc;
use rand::RngExt;
use serde_json::json;

const PURPOSE: &str = "delete-account";
const TOKEN_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteUserResult {
    Deleted,
    VerificationSent,
}

impl AuthService {
    pub async fn delete_current_user(
        &self,
        session: &SessionWithUser,
        password: Option<String>,
        token: Option<&str>,
        callback_url: Option<&str>,
    ) -> Result<DeleteUserResult, AuthError> {
        let config = &self.config.user.delete_user;
        if !config.enabled {
            return Err(AuthError::NotFound);
        }
        let password_provided = password.is_some();
        if let Some(password) = password {
            let hash = self.store.find_password_hash(session.user.id).await?;
            let Some(hash) = hash else {
                return Err(AuthError::CredentialAccountNotFound);
            };
            if !verify_password(password, Some(hash)).await? {
                return Err(AuthError::InvalidPassword);
            }
        }
        if let Some(token) = token {
            self.consume_delete_user_token(session, token).await?;
            self.delete_user_with_hooks(session.user.clone()).await?;
            return Ok(DeleteUserResult::Deleted);
        }
        if config.send_delete_account_verification.is_some() {
            self.send_delete_user_verification(session, callback_url)
                .await?;
            return Ok(DeleteUserResult::VerificationSent);
        }
        if !password_provided && session_is_stale(self, session) {
            return Err(AuthError::SessionExpired);
        }
        self.delete_user_with_hooks(session.user.clone()).await?;
        Ok(DeleteUserResult::Deleted)
    }

    pub async fn delete_current_user_callback(
        &self,
        session: &SessionWithUser,
        token: &str,
    ) -> Result<(), AuthError> {
        if !self.config.user.delete_user.enabled {
            return Err(AuthError::NotFound);
        }
        self.consume_delete_user_token(session, token).await?;
        self.delete_user_with_hooks(session.user.clone()).await
    }

    pub(super) async fn delete_user_with_hooks(
        &self,
        user: crate::AuthUser,
    ) -> Result<(), AuthError> {
        if let Some(callback) = &self.config.user.delete_user.before_delete {
            callback.call(user.clone()).await?;
        }
        self.plugins
            .before(&BeforeAuthEvent::UserDelete { user: user.clone() })
            .await?;
        self.delete_user_record_with_hooks(&user).await?;
        self.plugins
            .after(&AfterAuthEvent::UserDeleted { user: user.clone() })
            .await;
        if let Some(callback) = &self.config.user.delete_user.after_delete {
            callback.call(user).await?;
        }
        Ok(())
    }

    async fn send_delete_user_verification(
        &self,
        session: &SessionWithUser,
        callback_url: Option<&str>,
    ) -> Result<(), AuthError> {
        let config = &self.config.user.delete_user;
        let sender = config
            .send_delete_account_verification
            .as_ref()
            .ok_or(AuthError::NotFound)?;
        let token = delete_token();
        let now = Utc::now();
        self.create_verification_record(VerificationValue {
            purpose: PURPOSE.into(),
            identifier: hash_token(&token),
            payload: json!({ "userId": session.user.id }),
            additional_fields: serde_json::Map::new(),
            expires_at: now + config.delete_token_expires_in,
            created_at: now,
        })
        .await?;
        let mut url = self.config.base_url.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "a base URL is required for account-deletion verification".into(),
            )
        })?;
        url.set_path(&format!(
            "{}/delete-user/callback",
            self.config.base_path.trim_end_matches('/')
        ));
        url.set_query(None);
        url.query_pairs_mut()
            .append_pair("token", &token)
            .append_pair("callbackURL", callback_url.unwrap_or("/"));
        sender
            .send(DeleteAccountVerification {
                user: session.user.clone(),
                url: url.to_string(),
                token,
            })
            .await
    }

    async fn consume_delete_user_token(
        &self,
        session: &SessionWithUser,
        token: &str,
    ) -> Result<(), AuthError> {
        let value = self
            .consume_verification_record(PURPOSE, &hash_token(token), Utc::now())
            .await?
            .ok_or(AuthError::InvalidDeleteUserToken)?;
        let user_id = session.user.id.to_string();
        if value.payload.get("userId").and_then(|value| value.as_str()) != Some(user_id.as_str()) {
            return Err(AuthError::InvalidDeleteUserToken);
        }
        Ok(())
    }
}

fn session_is_stale(service: &AuthService, session: &SessionWithUser) -> bool {
    service.config.session_fresh_age != chrono::Duration::zero()
        && session.session.created_at + service.config.session_fresh_age <= Utc::now()
}

fn delete_token() -> String {
    let mut rng = rand::rng();
    (0..32)
        .map(|_| TOKEN_ALPHABET[rng.random_range(0..TOKEN_ALPHABET.len())] as char)
        .collect()
}
