#[cfg(feature = "axum")]
use super::oauth_state::OAuthCallbackResult;
use super::{
    AuthService, SignInResult,
    oauth_state::{OAuthLinkState, OAuthState},
    random_token,
};
use crate::{
    AuthError, AuthUser, AuthenticationMethod, DatabaseModel, DatabaseRecord, OAuthAccount,
    OAuthTokens, OAuthUserInfo, VerificationValue,
    oauth::{AuthorizationRequest, crypto},
};
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

    pub(super) async fn finish_oauth_sign_in(
        &self,
        provider: &dyn crate::SocialProvider,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
        request_sign_up: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SignInResult, bool), AuthError> {
        let now = Utc::now();
        let account = self.oauth_account(provider.id(), &user_info, tokens, now)?;
        let (user, is_new_user) = self
            .resolve_oauth_user(provider, user_info, account, request_sign_up, now)
            .await?;
        if provider.require_email_verification() && !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }
        let session = self
            .create_session(
                user,
                AuthenticationMethod::OAuth,
                None,
                ip_address,
                user_agent,
            )
            .await?;
        Ok((session, is_new_user))
    }

    async fn resolve_oauth_user(
        &self,
        provider: &dyn crate::SocialProvider,
        user_info: OAuthUserInfo,
        mut account: OAuthAccount,
        request_sign_up: bool,
        now: chrono::DateTime<Utc>,
    ) -> Result<(AuthUser, bool), AuthError> {
        if let Some(owner) = self
            .store
            .find_oauth_account_owner(&user_info.issuer, &user_info.account_id)
            .await?
        {
            account.id = owner.account.id;
            account.user_id = owner.user.id;
            account.created_at = owner.account.created_at;
            super::account_lifecycle::preserve_oauth_tokens(&mut account, &owner.account);
            let account = self.prepare_account_update(account).await?;
            let account = self.store.update_oauth_account_tokens(account).await?;
            self.finish_account_update(&account).await?;
            return Ok((owner.user, false));
        }
        if let Some(user) = self.store.find_user_by_email(&user_info.email).await? {
            let trusted = self
                .config
                .trusted_social_providers
                .iter()
                .any(|trusted| trusted == provider.id());
            let linking = &self.config.account.account_linking;
            if !linking.enabled
                || linking.disable_implicit_linking
                || (!trusted && !user_info.email_verified)
                || (linking.require_local_email_verified && !user.email_verified)
            {
                return Err(AuthError::OAuthAccountNotLinked);
            }
            account.user_id = user.id;
            let account = self.prepare_account_create(account).await?;
            let account = self.store.link_oauth_account(account).await?;
            self.finish_account_create(&account).await?;
            return Ok((user, false));
        }
        self.create_social_user(provider, user_info, account, request_sign_up, now)
            .await
    }

    async fn create_social_user(
        &self,
        provider: &dyn crate::SocialProvider,
        user_info: OAuthUserInfo,
        mut account: OAuthAccount,
        request_sign_up: bool,
        now: chrono::DateTime<Utc>,
    ) -> Result<(AuthUser, bool), AuthError> {
        if provider.disable_sign_up() || (provider.disable_implicit_sign_up() && !request_sign_up) {
            return Err(AuthError::OAuthSignupDisabled);
        }
        let user = AuthUser {
            id: Uuid::new_v4(),
            username: None,
            display_username: None,
            name: user_info.name,
            email: user_info.email,
            email_verified: user_info.email_verified,
            image: user_info.image,
            additional_fields: self
                .create_additional_fields(DatabaseModel::User, serde_json::Map::new())?,
            role: self.default_user_role(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        };
        let user = match self
            .before_database_create(DatabaseRecord::User(user))
            .await?
        {
            DatabaseRecord::User(user) => user,
            _ => unreachable!("database hook model was validated"),
        };
        account.user_id = user.id;
        let account = self.prepare_account_create(account).await?;
        let owner = self.store.create_oauth_user(user, account).await?;
        self.after_database_create(&DatabaseRecord::User(owner.user.clone()))
            .await?;
        self.finish_account_create(&owner.account).await?;
        Ok((owner.user, true))
    }

    pub(super) fn oauth_account(
        &self,
        provider_id: &str,
        user_info: &OAuthUserInfo,
        tokens: OAuthTokens,
        now: chrono::DateTime<Utc>,
    ) -> Result<OAuthAccount, AuthError> {
        Ok(OAuthAccount {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            issuer: user_info.issuer.clone(),
            account_id: user_info.account_id.clone(),
            provider_id: provider_id.into(),
            access_token: crypto::encrypt(&self.config.secret, tokens.access_token)?,
            refresh_token: crypto::encrypt(&self.config.secret, tokens.refresh_token)?,
            id_token: crypto::encrypt(&self.config.secret, tokens.id_token)?,
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
            password: None,
            additional_fields: serde_json::Map::new(),
            created_at: now,
            updated_at: now,
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
