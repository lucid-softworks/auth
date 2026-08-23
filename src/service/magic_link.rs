use super::{AuthService, SignInResult, email_password::normalize_email};
use crate::{
    Assurance, AuthError, AuthUser, MagicLinkConfig, MagicLinkEmail, MagicLinkRequestContext,
    MagicLinkTokenStorage, VerificationValue,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngExt;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PURPOSE: &str = "magic-link";
const TOKEN_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub(crate) struct MagicLinkRequest {
    pub email: String,
    pub name: Option<String>,
    pub callback_url: Option<String>,
    pub new_user_callback_url: Option<String>,
    pub error_callback_url: Option<String>,
    pub metadata: Option<Map<String, Value>>,
    pub context: MagicLinkRequestContext,
}

pub(crate) struct MagicLinkVerified {
    pub result: SignInResult,
    pub is_new_user: bool,
}

pub(crate) enum MagicLinkVerificationError {
    Redirect {
        code: &'static str,
        description: Option<&'static str>,
    },
    Auth(AuthError),
}

impl From<AuthError> for MagicLinkVerificationError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl AuthService {
    pub(crate) async fn send_magic_link(
        &self,
        config: &MagicLinkConfig,
        request: MagicLinkRequest,
    ) -> Result<(), AuthError> {
        self.enforce_magic_link_rate_limit(
            config,
            "sign-in",
            request.context.ip_address.as_deref(),
        )
        .await?;
        let email = request.email;
        normalize_email(&email)?;
        let token = match &config.token_generator {
            Some(generator) => generator.generate(&email).await?,
            None => default_token(),
        };
        if token.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "magic-link token generators must return a non-empty token".into(),
            ));
        }
        let identifier = magic_link_identifier(&config.token_storage, &token).await?;
        let now = Utc::now();
        self.store
            .create_verification(VerificationValue {
                purpose: PURPOSE.into(),
                identifier,
                payload: json!({ "email": email, "name": request.name }),
                expires_at: now + config.expires_in,
                created_at: now,
            })
            .await?;
        let message = MagicLinkEmail {
            email,
            url: self.magic_link_url(
                &token,
                request.callback_url.as_deref(),
                request.new_user_callback_url.as_deref(),
                request.error_callback_url.as_deref(),
            )?,
            token,
            metadata: request.metadata,
        };
        config.sender.send(message, request.context).await
    }

    pub(crate) async fn verify_magic_link(
        &self,
        config: &MagicLinkConfig,
        token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<MagicLinkVerified, MagicLinkVerificationError> {
        self.enforce_magic_link_rate_limit(config, "verify", ip_address.as_deref())
            .await?;
        let identifier = magic_link_identifier(&config.token_storage, token).await?;
        let Some(value) = self
            .store
            .consume_verification(PURPOSE, &identifier, Utc::now())
            .await?
        else {
            return redirect_error("INVALID_TOKEN", None);
        };
        let email = value
            .payload
            .get("email")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Storage("magic-link payload is invalid".into()))?;
        let name = value.payload.get("name").and_then(Value::as_str);
        let (mut user, is_new_user) = self.magic_link_user(config, email, name).await?;
        if !user.email_verified {
            let Some(promoted) = self.store.promote_email_owner(user.id, Utc::now()).await? else {
                return redirect_error("user_not_found", None);
            };
            user = promoted;
        }
        let result = self
            .create_session(user, Assurance::EmailVerified, None, ip_address, user_agent)
            .await?;
        Ok(MagicLinkVerified {
            result,
            is_new_user,
        })
    }

    async fn magic_link_user(
        &self,
        config: &MagicLinkConfig,
        email: &str,
        name: Option<&str>,
    ) -> Result<(AuthUser, bool), MagicLinkVerificationError> {
        if let Some(user) = self.store.find_user_by_email(email).await? {
            return Ok((user, false));
        }
        if config.disable_sign_up {
            return redirect_error("new_user_signup_disabled", None);
        }
        match self
            .store
            .create_user_without_account(new_magic_link_user(email, name))
            .await
        {
            Ok(user) => Ok((user, true)),
            Err(AuthError::UserAlreadyExists) => redirect_error(
                "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
                Some("User already exists. Use another email."),
            ),
            Err(error) => Err(error.into()),
        }
    }

    async fn enforce_magic_link_rate_limit(
        &self,
        config: &MagicLinkConfig,
        operation: &str,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError> {
        let key = format!(
            "magic-link:{operation}:{}",
            ip_address.unwrap_or("unknown-client")
        );
        let now = Utc::now();
        if self
            .store
            .rate_limit_exceeded(&key, now, config.rate_limit_max)
            .await?
        {
            return Err(AuthError::RateLimited);
        }
        self.store
            .record_auth_failure(&key, now, config.rate_limit_window)
            .await
    }

    fn magic_link_url(
        &self,
        token: &str,
        callback_url: Option<&str>,
        new_user_callback_url: Option<&str>,
        error_callback_url: Option<&str>,
    ) -> Result<String, AuthError> {
        let mut url = self.config.base_url.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "a base URL is required to send magic-link email".into(),
            )
        })?;
        url.set_path(&format!("{}/magic-link/verify", self.config.base_path));
        let mut query = url.query_pairs_mut();
        query.append_pair("token", token);
        query.append_pair("callbackURL", callback_url.unwrap_or("/"));
        if let Some(callback) = new_user_callback_url {
            query.append_pair("newUserCallbackURL", callback);
        }
        if let Some(callback) = error_callback_url {
            query.append_pair("errorCallbackURL", callback);
        }
        drop(query);
        Ok(url.into())
    }

    #[cfg(feature = "axum")]
    pub(crate) fn magic_link_callback_url(
        &self,
        callback_url: Option<&str>,
    ) -> Result<String, AuthError> {
        let base = self.config.base_url.clone().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "a base URL is required for magic-link redirects".into(),
            )
        })?;
        base.join(
            callback_url
                .filter(|value| !value.is_empty())
                .unwrap_or("/"),
        )
        .map(String::from)
        .map_err(|_| AuthError::InvalidCallbackUrl)
    }
}

fn new_magic_link_user(email: &str, name: Option<&str>) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: Uuid::new_v4(),
        username: None,
        display_username: None,
        name: name.unwrap_or("").to_owned(),
        email: email.to_owned(),
        email_verified: true,
        image: None,
        role: "member".into(),
        is_anonymous: false,
        must_change_password: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) async fn magic_link_identifier(
    storage: &MagicLinkTokenStorage,
    token: &str,
) -> Result<String, AuthError> {
    match storage {
        MagicLinkTokenStorage::Plain => Ok(token.to_owned()),
        MagicLinkTokenStorage::Hashed => {
            Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())))
        }
        MagicLinkTokenStorage::Custom(hasher) => hasher.hash(token).await,
    }
}

fn default_token() -> String {
    let mut rng = rand::rng();
    (0..32)
        .map(|_| TOKEN_ALPHABET[rng.random_range(0..TOKEN_ALPHABET.len())] as char)
        .collect()
}

fn redirect_error<T>(
    code: &'static str,
    description: Option<&'static str>,
) -> Result<T, MagicLinkVerificationError> {
    Err(MagicLinkVerificationError::Redirect { code, description })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_tokens_match_better_auths_alphabet_and_hash_profile() {
        let token = default_token();
        assert_eq!(token.len(), 32);
        assert!(token.bytes().all(|byte| TOKEN_ALPHABET.contains(&byte)));
        let hashed = magic_link_identifier(&MagicLinkTokenStorage::Hashed, &token)
            .await
            .unwrap();
        assert_eq!(hashed.len(), 43);
        assert_ne!(hashed, token);
    }
}
