#[cfg(feature = "axum")]
use super::oauth_state::OAuthCallbackResult;
use super::{
    AuthService, SignInResult,
    oauth_state::{OAuthLinkState, OAuthState},
    random_token,
};
use crate::{AuthError, VerificationValue, oauth::AuthorizationRequest};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

const STATE_PURPOSE: &str = "oauth-state";

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
    },
    Session(Box<SignInResult>),
    Linked,
}

impl AuthService {
    pub(super) async fn start_social_authorization(
        &self,
        provider: &dyn crate::SocialProvider,
        input: SocialSignInInput,
        link: Option<OAuthLinkState>,
        anonymous_user_id: Option<Uuid>,
    ) -> Result<SocialSignInResult, AuthError> {
        let base_url = self.oauth_base_url()?;
        let callback_url = input.callback_url.unwrap_or_else(|| base_url.clone());
        let state = random_token();
        let mut code_verifier = format!("{}{}{}", random_token(), random_token(), random_token());
        code_verifier.truncate(128);
        let id_token_nonce = provider.requires_id_token_nonce().then(random_token);
        let state_data = OAuthState {
            provider: input.provider,
            callback_url,
            code_verifier: code_verifier.clone(),
            error_url: input.error_callback_url,
            new_user_url: input.new_user_callback_url,
            request_sign_up: input.request_sign_up,
            id_token_nonce: id_token_nonce.clone(),
            additional_data: input.additional_data,
            link,
            anonymous_user_id,
        };
        self.save_oauth_state(&state, &state_data).await?;
        let url = provider.create_authorization_url(&AuthorizationRequest {
            state: state.clone(),
            code_verifier,
            id_token_nonce,
            redirect_uri: self.oauth_callback_url(provider.id())?,
            scopes: input.scopes,
            login_hint: input.login_hint,
            additional_params: input.additional_params,
        })?;
        Ok(SocialSignInResult::Authorization {
            url: url.into(),
            redirect: !input.disable_redirect,
            state,
        })
    }

    async fn save_oauth_state(&self, state: &str, value: &OAuthState) -> Result<(), AuthError> {
        let now = Utc::now();
        self.create_verification_record(VerificationValue {
            purpose: STATE_PURPOSE.into(),
            identifier: state.into(),
            payload: serde_json::to_value(value).map_err(|_| AuthError::OAuthStateMismatch)?,
            additional_fields: serde_json::Map::new(),
            expires_at: now + Duration::minutes(10),
            created_at: now,
        })
        .await
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn oauth_state(&self, state: &str) -> Result<OAuthState, AuthError> {
        let value = self
            .find_verification_value(STATE_PURPOSE, state)
            .await?
            .filter(|value| value.expires_at > Utc::now())
            .ok_or(AuthError::OAuthStateMismatch)?;
        serde_json::from_value(value.payload).map_err(|_| AuthError::OAuthStateMismatch)
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn consume_oauth_state(&self, state: &str) -> Result<(), AuthError> {
        self.consume_verification_record(STATE_PURPOSE, state, Utc::now())
            .await?
            .ok_or(AuthError::OAuthStateMismatch)
            .map(|_| ())
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
        if state.provider != provider_id {
            return Err(AuthError::OAuthStateMismatch);
        }
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
            .await?;
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
