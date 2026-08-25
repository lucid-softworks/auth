use super::{
    OAuthProxyPlugin, OAuthProxySecret, crypto,
    payload::{OAuthProxyAccount, OAuthProxyPayload, OAuthProxyStatePackage, OAuthProxyUserInfo},
    url::callback_destination,
};
use crate::{AuthError, AuthService, OAuthTokens, OAuthUserInfo, SocialSignInResult};
use chrono::Utc;
use serde_json::Value;
use url::Url;

pub(crate) enum ProxyCallbackOutcome {
    Redirect(String),
    Error {
        error_url: String,
        code: String,
        description: Option<String>,
    },
    InternalError,
}

pub(crate) fn secret(service: &AuthService, plugin: &OAuthProxyPlugin) -> OAuthProxySecret {
    plugin
        .config()
        .secret
        .clone()
        .unwrap_or_else(|| service.oauth_proxy_default_secret())
}

pub(crate) async fn wrap_authorization(
    service: &AuthService,
    plugin: &OAuthProxyPlugin,
    result: &mut SocialSignInResult,
) {
    let SocialSignInResult::Authorization {
        url,
        state,
        state_cookie_name,
        state_cookie_value,
        ..
    } = result
    else {
        return;
    };
    let cookie = (*state_cookie_name == "oauth_state").then_some(state_cookie_value.as_str());
    let prepared = async {
        let state_data = service.oauth_state(state, cookie).await.ok()?;
        let plaintext = serde_json::to_vec(&state_data).ok()?;
        let key = secret(service, plugin);
        let state_cookie = crypto::encrypt(&key, &plaintext).ok()?;
        let package = serde_json::to_vec(&OAuthProxyStatePackage {
            state: state.clone(),
            state_cookie,
            is_o_auth_proxy: true,
        })
        .ok()?;
        let package = crypto::encrypt(&key, &package).ok()?;
        let mut provider_url = Url::parse(url).ok()?;
        set_query_parameter(&mut provider_url, "state", &package);
        Some(provider_url.to_string())
    }
    .await;
    if let Some(prepared) = prepared {
        *url = prepared;
    }
}

pub(crate) async fn provider_callback(
    service: &AuthService,
    plugin: &OAuthProxyPlugin,
    provider_id: &str,
    state_token: &str,
    code: Option<&str>,
    provider_error: Option<&str>,
    provider_user: Option<&Value>,
) -> Option<ProxyCallbackOutcome> {
    let key = secret(service, plugin);
    let package = decrypt_json::<OAuthProxyStatePackage>(&key, state_token)?;
    if !package.is_o_auth_proxy || package.state.is_empty() || package.state_cookie.is_empty() {
        return None;
    }
    let state = decrypt_json::<crate::service::OAuthState>(&key, &package.state_cookie)?;
    let error_url = state
        .error_url
        .clone()
        .or_else(|| {
            service
                .oauth_base_url()
                .ok()
                .map(|base| format!("{base}/error"))
        })
        .unwrap_or_else(|| "/api/auth/error".into());
    if state
        .oauth_state
        .as_deref()
        .is_some_and(|bound| bound != package.state)
    {
        return Some(proxy_error(error_url, "state_mismatch"));
    }
    if let Some(error) = provider_error {
        return Some(proxy_error(error_url, error));
    }
    let Some(code) = code else {
        return Some(proxy_error(error_url, "no_code"));
    };
    let Some(provider) = service.social_provider(provider_id) else {
        return Some(proxy_error(error_url, "oauth_provider_not_found"));
    };
    let redirect_uri = match service.oauth_callback_url(provider.id()) {
        Ok(url) => url,
        Err(_) => return Some(ProxyCallbackOutcome::InternalError),
    };
    let tokens = match provider
        .exchange_code(code, &state.code_verifier, &redirect_uri, None)
        .await
    {
        Ok(tokens) => tokens,
        Err(_) => return Some(proxy_error(error_url, "invalid_code")),
    };
    // Better Auth 1.7.1 intentionally does not forward the stored nonce here.
    let user_info = match provider.get_user_info(&tokens, None, provider_user).await {
        Ok(user_info) => user_info,
        Err(_) => return Some(proxy_error(error_url, "unable_to_get_user_info")),
    };
    if user_info.email.is_empty() {
        return Some(proxy_error(error_url, "email_not_found"));
    }
    Some(profile_redirect(
        service,
        plugin,
        provider.as_ref(),
        tokens,
        user_info,
        package.state,
        state,
    ))
}

fn profile_redirect(
    service: &AuthService,
    plugin: &OAuthProxyPlugin,
    provider: &dyn crate::SocialProvider,
    tokens: OAuthTokens,
    user_info: OAuthUserInfo,
    state_token: String,
    state: crate::service::OAuthState,
) -> ProxyCallbackOutcome {
    let mut proxy_callback = match Url::parse(&state.callback_url) {
        Ok(url) => url,
        Err(_) => return ProxyCallbackOutcome::InternalError,
    };
    let callback_url = callback_destination(&proxy_callback);
    let payload = payload_from_provider(
        provider,
        tokens,
        user_info,
        state_token,
        callback_url,
        state,
    );
    let plaintext = match serde_json::to_vec(&payload) {
        Ok(payload) => payload,
        Err(_) => return ProxyCallbackOutcome::InternalError,
    };
    let encrypted = match crypto::encrypt(&secret(service, plugin), &plaintext) {
        Ok(encrypted) => encrypted,
        Err(_) => return ProxyCallbackOutcome::InternalError,
    };
    set_query_parameter(&mut proxy_callback, "profile", &encrypted);
    ProxyCallbackOutcome::Redirect(proxy_callback.to_string())
}

fn payload_from_provider(
    provider: &dyn crate::SocialProvider,
    tokens: OAuthTokens,
    user_info: OAuthUserInfo,
    state_token: String,
    callback_url: String,
    state: crate::service::OAuthState,
) -> OAuthProxyPayload {
    let scope = (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(","));
    OAuthProxyPayload {
        user_info: OAuthProxyUserInfo {
            id: user_info.account_id.clone(),
            email: user_info.email.clone(),
            name: user_info.name.clone(),
            image: user_info.image.clone(),
            email_verified: Some(user_info.email_verified),
        },
        profile: Some(Value::Object(user_info.profile)),
        account: OAuthProxyAccount {
            provider_id: provider.id().into(),
            issuer: user_info.issuer,
            account_id: user_info.account_id,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            id_token: tokens.id_token,
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope,
        },
        state: state_token,
        callback_url,
        new_user_url: state.new_user_url,
        error_url: state.error_url,
        disable_sign_up: (provider.disable_implicit_sign_up() && !state.request_sign_up)
            || provider.disable_sign_up(),
        timestamp: Utc::now().timestamp_millis(),
    }
}

pub(crate) async fn finish_callback(
    service: &AuthService,
    plugin: &OAuthProxyPlugin,
    profile: &str,
    state_cookie: Option<&str>,
    ip_address: Option<String>,
    user_agent: Option<String>,
) -> Result<(crate::SignInResult, bool, OAuthProxyPayload), ProxyCompletionError> {
    let key = secret(service, plugin);
    let plaintext = crypto::decrypt(&key, profile)
        .map_err(|_| ProxyCompletionError::new("invalid_profile", None))?;
    let payload: OAuthProxyPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| ProxyCompletionError::new("invalid_payload", None))?;
    if payload.user_info.email.is_empty()
        || payload.account.provider_id.is_empty()
        || payload.account.issuer.is_empty()
        || payload.account.account_id.is_empty()
        || payload.state.is_empty()
        || payload.callback_url.is_empty()
    {
        return Err(ProxyCompletionError::new("invalid_payload", None));
    }
    let error_url = payload.error_url.clone();
    if !payload.is_within_age(Utc::now().timestamp_millis(), plugin.config().max_age) {
        return Err(ProxyCompletionError::new("payload_expired", error_url));
    }
    service
        .validate_and_consume_oauth_proxy_state(&payload.state, state_cookie)
        .await
        .map_err(|_| ProxyCompletionError::new("state_mismatch", error_url.clone()))?;
    let tokens = OAuthTokens {
        access_token: payload.account.access_token.clone(),
        refresh_token: payload.account.refresh_token.clone(),
        id_token: payload.account.id_token.clone(),
        access_token_expires_at: payload.account.access_token_expires_at,
        refresh_token_expires_at: payload.account.refresh_token_expires_at,
        scopes: payload
            .account
            .scope
            .as_deref()
            .map(|scope| scope.split(',').map(str::to_owned).collect())
            .unwrap_or_default(),
        extra: serde_json::Map::new(),
    };
    let user_info = OAuthUserInfo {
        account_id: payload.account.account_id.clone(),
        issuer: payload.account.issuer.clone(),
        name: payload.user_info.name.clone(),
        email: payload.user_info.email.clone(),
        email_verified: payload.user_info.email_verified.unwrap_or(false),
        image: payload.user_info.image.clone(),
        additional_fields: serde_json::Map::new(),
        profile: payload
            .profile
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
    };
    let result = service
        .finish_oauth_proxy_sign_in(
            payload.account.provider_id.clone(),
            tokens,
            user_info,
            payload.disable_sign_up,
            ip_address,
            user_agent,
        )
        .await
        .map_err(|error| ProxyCompletionError::auth(error, error_url))?;
    Ok((result.0, result.1, payload))
}

fn decrypt_json<T: serde::de::DeserializeOwned>(
    secret: &OAuthProxySecret,
    ciphertext: &str,
) -> Option<T> {
    serde_json::from_slice(&crypto::decrypt(secret, ciphertext).ok()?).ok()
}

fn set_query_parameter(url: &mut Url, name: &str, value: &str) {
    let retained = url
        .query_pairs()
        .filter(|(candidate, _)| candidate != name)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair(name, value);
}

fn proxy_error(error_url: String, code: &str) -> ProxyCallbackOutcome {
    ProxyCallbackOutcome::Error {
        error_url,
        code: code.into(),
        description: None,
    }
}

pub(crate) struct ProxyCompletionError {
    pub code: String,
    pub error_url: Option<String>,
    pub description: Option<String>,
    pub clear_state_cookie: bool,
}

impl ProxyCompletionError {
    fn new(code: &str, error_url: Option<String>) -> Self {
        Self {
            code: code.into(),
            error_url,
            description: None,
            clear_state_cookie: false,
        }
    }

    fn auth(error: AuthError, error_url: Option<String>) -> Self {
        Self {
            code: callback_error_code(&error).into(),
            error_url,
            description: None,
            clear_state_cookie: true,
        }
    }
}

fn callback_error_code(error: &AuthError) -> &'static str {
    match error {
        AuthError::OAuthAccountNotLinked => "account_not_linked",
        AuthError::OAuthSignupDisabled => "signup_disabled",
        AuthError::OAuthUnableToUpdateAccount => "unable_to_update_account",
        AuthError::OAuthUnableToCreateUser => "unable_to_create_user",
        AuthError::OAuthUnableToCreateSession => "unable_to_create_session",
        AuthError::OAuthUnableToLinkAccount => "unable_to_link_account",
        AuthError::EmailNotVerified => "email_not_verified",
        _ => "internal_server_error",
    }
}
