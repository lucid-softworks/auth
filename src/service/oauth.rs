#[cfg(feature = "axum")]
use super::oauth_state::OAuthCallbackResult;
use super::{
    AuthService, SignInResult,
    oauth_state::{OAuthLinkState, OAuthState},
};
use crate::{AuthError, VerificationValue, oauth::AuthorizationRequest};
use chrono::{Duration, Utc};
use rand::RngExt;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocialSignInInput {
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(default)]
    pub disable_redirect: bool,
    pub id_token: Option<SocialIdTokenInput>,
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub request_sign_up: bool,
    pub login_hint: Option<String>,
    #[serde(default)]
    pub additional_params: BTreeMap<String, String>,
    #[serde(default)]
    pub additional_data: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocialIdTokenInput {
    pub token: String,
    pub nonce: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
    pub user: Option<Value>,
}

#[derive(Debug, Clone)]
pub enum SocialSignInResult {
    Authorization {
        url: String,
        redirect: bool,
        state: String,
        state_cookie_name: &'static str,
        state_cookie_value: String,
        state_cookie_max_age: i64,
    },
    Session(Box<SignInResult>),
    Linked,
}

impl AuthService {
    #[cfg(feature = "axum")]
    pub(crate) async fn restart_idp_initiated_authorization(
        &self,
        provider_id: &str,
    ) -> Result<(String, &'static str, String, i64), AuthError> {
        let provider = self
            .social_provider(provider_id)
            .filter(|provider| provider.allow_idp_initiated())
            .ok_or(AuthError::OAuthProviderNotFound)?;
        let input = SocialSignInInput {
            provider: provider_id.into(),
            callback_url: None,
            new_user_callback_url: None,
            error_callback_url: None,
            disable_redirect: false,
            id_token: None,
            scopes: None,
            request_sign_up: false,
            login_hint: None,
            additional_params: BTreeMap::new(),
            additional_data: serde_json::Map::new(),
        };
        match self
            .start_social_authorization(provider.as_ref(), input, None, None, None)
            .await?
        {
            SocialSignInResult::Authorization {
                url,
                state_cookie_name,
                state_cookie_value,
                state_cookie_max_age,
                ..
            } => Ok((
                url,
                state_cookie_name,
                state_cookie_value,
                state_cookie_max_age,
            )),
            _ => Err(AuthError::OAuthProviderNotFound),
        }
    }

    pub(super) async fn start_social_authorization(
        &self,
        provider: &dyn crate::SocialProvider,
        input: SocialSignInInput,
        link: Option<OAuthLinkState>,
        anonymous_user_id: Option<Uuid>,
        redirect_uri: Option<String>,
    ) -> Result<SocialSignInResult, AuthError> {
        let base_url = self.oauth_base_url()?;
        let callback_url = input
            .callback_url
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| base_url.clone());
        let state = random_oauth_string(32);
        let code_verifier = random_oauth_string(128);
        let id_token_nonce = provider
            .requires_id_token_nonce()
            .then(|| random_oauth_string(32));
        let mut additional_data = input.additional_data;
        for reserved in [
            "oauthState",
            "callbackURL",
            "codeVerifier",
            "errorURL",
            "newUserURL",
            "expiresAt",
            "requestSignUp",
            "idTokenNonce",
            "link",
            "anonymousUserId",
        ] {
            additional_data.remove(reserved);
        }
        let state_data = OAuthState {
            oauth_state: Some(state.clone()),
            callback_url,
            code_verifier: code_verifier.clone(),
            error_url: input.error_callback_url,
            new_user_url: input.new_user_callback_url,
            expires_at: (Utc::now() + Duration::minutes(10)).timestamp_millis(),
            request_sign_up: input.request_sign_up,
            id_token_nonce: id_token_nonce.clone(),
            additional_data,
            link,
            anonymous_user_id,
        };
        let (state_cookie_name, state_cookie_value, state_cookie_max_age) =
            self.save_oauth_state(&state, &state_data).await?;
        let url = provider.create_authorization_url(&AuthorizationRequest {
            state: state.clone(),
            code_verifier,
            id_token_nonce,
            redirect_uri: redirect_uri.unwrap_or(self.oauth_callback_url(provider.id())?),
            scopes: input.scopes,
            login_hint: input.login_hint,
            additional_params: input.additional_params,
        })?;
        Ok(SocialSignInResult::Authorization {
            url: url.into(),
            redirect: !input.disable_redirect,
            state,
            state_cookie_name,
            state_cookie_value,
            state_cookie_max_age,
        })
    }

    pub(crate) async fn save_oauth_state(
        &self,
        state: &str,
        value: &OAuthState,
    ) -> Result<(&'static str, String, i64), AuthError> {
        if self.config.account.store_state_strategy == crate::OAuthStateStrategy::Cookie {
            #[cfg(feature = "axum")]
            {
                let data = serde_json::to_vec(value).map_err(|_| AuthError::OAuthStateMismatch)?;
                let encoded = crate::symmetric_crypto::encrypt_versioned(
                    &self.config.secret,
                    self.config.versioned_secrets(),
                    &data,
                )
                .map_err(|_| AuthError::Worker)?;
                return Ok(("oauth_state", encoded, 600));
            }
            #[cfg(not(feature = "axum"))]
            return Err(AuthError::InvalidConfiguration(
                "cookie OAuth state requires the axum feature".into(),
            ));
        }
        let now = Utc::now();
        self.create_verification_record(VerificationValue::new(
            state,
            serde_json::to_string(value).map_err(|_| AuthError::OAuthStateMismatch)?,
            now + Duration::minutes(10),
        ))
        .await
        .map_err(|_| AuthError::OAuthStateGenerationFailed)?;
        Ok(("state", self.signed_cookie_value(state), 300))
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn oauth_state(
        &self,
        state: &str,
        cookie_value: Option<&str>,
    ) -> Result<OAuthState, AuthError> {
        if self.config.account.store_state_strategy == crate::OAuthStateStrategy::Cookie {
            let value = cookie_value.ok_or(AuthError::OAuthStateMismatch)?;
            let plaintext = crate::symmetric_crypto::decrypt_versioned(
                &self.config.secret,
                self.config.versioned_secrets(),
                self.config.legacy_secret(),
                value,
            )
            .map_err(|_| AuthError::OAuthStateInvalid)?;
            let state_data: OAuthState =
                serde_json::from_slice(&plaintext).map_err(|_| AuthError::OAuthStateInvalid)?;
            return Ok(state_data);
        }
        let value = self
            .find_verification_value(state)
            .await?
            .ok_or(AuthError::OAuthStateMismatch)?;
        let state_data: OAuthState = serde_json::from_str(&value.value)
            .map_err(|_| AuthError::Storage("OAuth state payload is invalid".into()))?;
        Ok(state_data)
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn consume_oauth_state(&self, state: &str) -> Result<(), AuthError> {
        if self.config.account.store_state_strategy == crate::OAuthStateStrategy::Cookie {
            return Ok(());
        }
        self.consume_verification_record(state, Utc::now())
            .await?
            .ok_or(AuthError::OAuthStateMismatch)
            .map(|_| ())
    }

    #[cfg(feature = "axum")]
    pub(crate) fn oauth_state_cookie_name(&self) -> &'static str {
        match self.config.account.store_state_strategy {
            crate::OAuthStateStrategy::Database => "state",
            crate::OAuthStateStrategy::Cookie => "oauth_state",
        }
    }

    #[cfg(feature = "axum")]
    pub(crate) fn skip_oauth_state_cookie_check(&self) -> bool {
        self.config.account.skip_state_cookie_check
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "axum")]
    pub(crate) async fn oauth_callback(
        &self,
        provider_id: &str,
        code: &str,
        state: OAuthState,
        issuer: Option<&str>,
        device_id: Option<&str>,
        provider_user: Option<&Value>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<OAuthCallbackResult, AuthError> {
        let provider = self
            .social_provider(provider_id)
            .ok_or(AuthError::OAuthProviderNotFound)?;
        if let (Some(received), Some(expected)) = (issuer, provider.issuer())
            && received != expected
        {
            return Err(AuthError::OAuthIssuerMismatch);
        }
        if provider.requires_id_token_nonce() && state.id_token_nonce.is_none() {
            return Err(AuthError::OAuthNonceBindingMissing);
        }
        let redirect_uri = self.oauth_callback_url(provider.id())?;
        let tokens = provider
            .exchange_code(code, &state.code_verifier, &redirect_uri, device_id)
            .await
            .map_err(|_| AuthError::OAuthInvalidCode)?;
        let user_info = provider
            .get_user_info(&tokens, state.id_token_nonce.as_deref(), provider_user)
            .await?;
        if let Some(link) = &state.link {
            self.link_oauth_identity(provider.as_ref(), link, tokens, user_info)
                .await?;
            return Ok(OAuthCallbackResult {
                session: None,
                redirect_url: state.callback_url,
                is_new_user: false,
            });
        }
        let (session, is_new_user) = self
            .finish_oauth_sign_in(
                provider.as_ref(),
                tokens,
                user_info,
                state.request_sign_up,
                ip_address,
                user_agent,
            )
            .await?;
        if let Some(source) = self
            .anonymous_upgrade_source(state.anonymous_user_id)
            .await?
        {
            self.complete_anonymous_upgrade(&source, &session).await?;
        }
        let redirect_url = if is_new_user {
            state.new_user_url.unwrap_or(state.callback_url)
        } else {
            state.callback_url
        };
        Ok(OAuthCallbackResult {
            session: Some(session),
            redirect_url,
            is_new_user,
        })
    }

    pub(crate) fn oauth_base_url(&self) -> Result<String, AuthError> {
        let mut url =
            self.config.base_url.as_ref().cloned().ok_or_else(|| {
                AuthError::InvalidConfiguration("OAuth requires a base URL".into())
            })?;
        if url.path() == "/" {
            url.set_path(self.config.base_path());
        }
        Ok(url.as_str().trim_end_matches('/').to_owned())
    }

    pub(crate) fn oauth_callback_url(&self, provider_id: &str) -> Result<String, AuthError> {
        Ok(format!("{}/callback/{provider_id}", self.oauth_base_url()?))
    }
}

fn random_oauth_string(length: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}
