use super::AuthService;
use crate::{
    AuthError, OneTimeTokenConfig, OneTimeTokenError, OneTimeTokenRequestContext,
    OneTimeTokenStorage, SessionWithUser, VerificationValue,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngExt;
use sha2::{Digest, Sha256};

const IDENTIFIER_PREFIX: &str = "one-time-token:";
const TOKEN_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";

impl AuthService {
    /// Generates a Better Auth one-time token for an existing session.
    ///
    /// This native API remains available when HTTP generation is disabled,
    /// matching Better Auth's `disableClientRequest` behavior.
    pub async fn generate_one_time_token(
        &self,
        session: &SessionWithUser,
        context: OneTimeTokenRequestContext,
    ) -> Result<String, AuthError> {
        let config = self.one_time_token_config()?;
        self.generate_one_time_token_with(config, session, &context)
            .await
    }

    /// Atomically redeems a one-time token and returns its bound live session.
    pub async fn verify_one_time_token(&self, token: &str) -> Result<SessionWithUser, AuthError> {
        let config = self.one_time_token_config()?;
        let session = self.consume_one_time_token_with(config, token).await?;
        if session.session.expires_at < Utc::now() {
            return Err(OneTimeTokenError::SessionExpired.into());
        }
        Ok(session)
    }

    pub(crate) fn one_time_token_config(&self) -> Result<&OneTimeTokenConfig, AuthError> {
        self.plugins
            .find::<crate::OneTimeTokenPlugin>()
            .map(crate::OneTimeTokenPlugin::config)
            .ok_or_else(|| {
                AuthError::InvalidConfiguration("the one-time-token plugin is not enabled".into())
            })
    }

    pub(crate) async fn generate_one_time_token_with(
        &self,
        config: &OneTimeTokenConfig,
        session: &SessionWithUser,
        context: &OneTimeTokenRequestContext,
    ) -> Result<String, AuthError> {
        let token = match &config.generator {
            Some(generator) => generator.generate(session, context).await?,
            None => default_token(),
        };
        let identifier = stored_token(&config.token_storage, &token).await?;
        let now = Utc::now();
        self.replace_verification_with_create_hooks(VerificationValue::new(
            format!("{IDENTIFIER_PREFIX}{identifier}"),
            session.session.token.clone(),
            now + config.expires_in,
        ))
        .await?;
        Ok(token)
    }

    pub(crate) async fn consume_one_time_token_with(
        &self,
        config: &OneTimeTokenConfig,
        token: &str,
    ) -> Result<SessionWithUser, AuthError> {
        let identifier = stored_token(&config.token_storage, token).await?;
        let Some(value) = self
            .consume_verification_record(&format!("{IDENTIFIER_PREFIX}{identifier}"), Utc::now())
            .await?
        else {
            return Err(OneTimeTokenError::InvalidToken.into());
        };
        self.find_stored_session(&value.value)
            .await?
            .ok_or_else(|| OneTimeTokenError::SessionNotFound.into())
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn session_being_bound(&self, token: &str) -> Option<SessionWithUser> {
        if !self
            .plugins
            .find::<crate::OneTimeTokenPlugin>()
            .is_some_and(|plugin| plugin.config().set_ott_header_on_new_session)
        {
            return None;
        }
        if let Ok(Some(session)) = self.find_stored_session(token).await {
            return Some(session);
        }
        self.pending_stateless_sessions
            .lock()
            .await
            .get(token)
            .cloned()
    }
}

async fn stored_token(storage: &OneTimeTokenStorage, token: &str) -> Result<String, AuthError> {
    match storage {
        OneTimeTokenStorage::Plain => Ok(token.to_owned()),
        OneTimeTokenStorage::Hashed => Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))),
        OneTimeTokenStorage::Custom(hasher) => hasher.hash(token).await,
    }
}

fn default_token() -> String {
    let mut rng = rand::rng();
    (0..32)
        .map(|_| TOKEN_ALPHABET[rng.random_range(0..TOKEN_ALPHABET.len())] as char)
        .collect()
}
