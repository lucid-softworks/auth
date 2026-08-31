use super::{redirect_error, support};
use crate::{
    AuthService, SocialProvider as _, SsoPlugin, SsoPrivateKey, SsoPrivateKeyRequest, SsoProvider,
    service::OAuthState,
};
use axum::{
    http::{HeaderMap, HeaderValue},
    response::Response,
};

pub(super) struct Input {
    pub provider: SsoProvider,
    pub provider_reference: crate::SsoProviderReference,
    pub code: String,
    pub state_token: String,
    pub state: OAuthState,
    pub error_url: String,
}

pub(super) async fn finish(
    service: &AuthService,
    plugin: &SsoPlugin,
    headers: &HeaderMap,
    input: Input,
) -> Response {
    let Input {
        mut provider,
        provider_reference,
        code,
        state_token,
        state,
        error_url,
    } = input;
    let Some(config) = provider.oidc_config.as_ref().and_then(serde_json::Value::as_object) else {
        return redirect_error(&error_url, "invalid_provider", "provider not found");
    };
    let override_user_info = override_user_info(plugin, config);
    provider.oidc_config = match super::super::runtime_oidc::ensure(
        service,
        &provider.issuer,
        config,
    )
    .await
    {
        Ok(config) => Some(serde_json::Value::Object(config)),
        Err(error) => return redirect_error(&error_url, "discovery_failed", &error.message),
    };
    let private_key = match resolve_private_key(plugin, &provider).await {
        Ok(material) => material,
        Err(()) => {
            return redirect_error(
                &error_url,
                "invalid_provider",
                "no_private_key_available",
            );
        }
    };
    let redirect_uri = support::oidc_redirect_uri(service, plugin, &provider.provider_id);
    let dynamic = match super::super::super::oidc_provider::build(
        &provider,
        redirect_uri.clone(),
        plugin.options(),
        private_key,
    ) {
        Ok(provider) => provider,
        Err(description) => return redirect_error(&error_url, "invalid_provider", description),
    };
    if service.consume_oauth_state(&state_token).await.is_err() {
        return redirect_error(&error_url, "invalid_state", "state_already_used");
    }
    let (tokens, user_info) = match exchange_identity(&dynamic, &code, &state, &redirect_uri).await {
        Ok(identity) => identity,
        Err(error) => return callback_error_response(&error_url, &error),
    };
    let resolution_input = match super::super::resolution::oidc_input(
        plugin,
        &provider,
        provider_reference.clone(),
        &tokens,
        &user_info,
    ) {
        Ok(input) => input,
        Err(error) => return callback_error_response(&error_url, &error),
    };
    complete_sign_in(
        service,
        plugin,
        headers,
        provider,
        provider_reference,
        resolution_input,
        state,
        override_user_info,
        tokens,
        user_info,
        &error_url,
    )
    .await
}

async fn exchange_identity(
    provider: &crate::generic_oauth::GenericOAuthProvider,
    code: &str,
    state: &OAuthState,
    redirect_uri: &str,
) -> Result<(crate::OAuthTokens, crate::OAuthUserInfo), crate::AuthError> {
    let tokens = provider
        .exchange_code(code, &state.code_verifier, redirect_uri, None)
        .await
        .map_err(|_| crate::AuthError::OAuthInvalidCode)?;
    let user_info = provider
        .get_user_info(&tokens, state.id_token_nonce.as_deref(), None)
        .await?;
    Ok((tokens, user_info))
}

fn override_user_info(plugin: &SsoPlugin, config: &serde_json::Map<String, serde_json::Value>) -> bool {
    config
        .get("overrideUserInfo")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(plugin.options().default_override_user_info)
}

#[allow(clippy::too_many_arguments)]
async fn complete_sign_in(
    service: &AuthService,
    plugin: &SsoPlugin,
    headers: &HeaderMap,
    provider: SsoProvider,
    provider_reference: crate::SsoProviderReference,
    resolution_input: crate::SsoUserResolutionInput,
    state: OAuthState,
    override_user_info: bool,
    tokens: crate::OAuthTokens,
    user_info: crate::OAuthUserInfo,
    error_url: &str,
) -> Response {
    let result = match super::super::resolution::finish(
        service,
        plugin,
        super::super::resolution::FinishInput {
            provider: provider.clone(),
            provider_reference,
            resolution_input,
            tokens: tokens.clone(),
            user_info: user_info.clone(),
            state,
            override_user_info,
            user_agent: crate::axum::http::user_agent(headers),
        },
    )
        .await
    {
        Ok(result) => result,
        Err(error) => return callback_error_response(error_url, &error),
    };
    if let Err(response) = provision(
        service,
        plugin,
        &provider,
        &user_info,
        Some(tokens),
        &result,
    )
    .await
    {
        return *response;
    }
    success(service, headers, &provider.provider_id, result).await
}

pub(in crate::sso::axum) async fn provision(
    service: &AuthService,
    plugin: &SsoPlugin,
    provider: &SsoProvider,
    user_info: &crate::OAuthUserInfo,
    tokens: Option<crate::OAuthTokens>,
    result: &crate::OAuthCallbackResult,
) -> Result<(), Box<Response>> {
    let Some(sign_in) = result.session.as_ref() else {
        return Ok(());
    };
    plugin
        .provision_user(
            crate::SsoProvisioningInput {
                user: sign_in.session.user.clone(),
                user_info: user_info.clone(),
                tokens: tokens.clone(),
                provider: provider.clone(),
            },
            result.is_new_user,
        )
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "SSO user provisioning failed");
            Box::new(support::error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                "Unable to provision SSO user",
            ))
        })?;
    super::super::super::organization_provisioning::assign_from_provider(
        service,
        plugin,
        &sign_in.session.user,
        user_info,
        tokens,
        provider,
    )
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "SSO organization provisioning failed");
        Box::new(support::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Unable to provision SSO organization membership",
        ))
    })
}

async fn resolve_private_key(
    plugin: &SsoPlugin,
    provider: &SsoProvider,
) -> Result<Option<SsoPrivateKey>, ()> {
    let config = provider
        .oidc_config
        .as_ref()
        .and_then(serde_json::Value::as_object);
    if config
        .and_then(|config| config.get("tokenEndpointAuthentication"))
        .and_then(serde_json::Value::as_str)
        != Some("private_key_jwt")
    {
        return Ok(None);
    }
    plugin
        .resolve_private_key(SsoPrivateKeyRequest {
            provider_id: provider.provider_id.clone(),
            key_id: config
                .and_then(|config| config.get("privateKeyId"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            issuer: provider.issuer.clone(),
        })
        .await
        .map_err(|_| ())
}

pub(in crate::sso::axum) fn callback_error(
    error: &crate::AuthError,
) -> (&'static str, &'static str) {
    use crate::AuthError::{
        OAuthIdTokenNotVerified, OAuthIdTokenSubjectMissing,
        OAuthIdTokenUserInfoSubjectMismatch, OAuthMissingUserInfo, OAuthUserInfoEndpointNotFound,
    };
    match error {
        OAuthIdTokenNotVerified => ("invalid_provider", "token_not_verified"),
        OAuthIdTokenSubjectMissing => ("invalid_provider", "id_token_subject_missing"),
        OAuthIdTokenUserInfoSubjectMismatch => {
            ("invalid_provider", "id_token_userinfo_subject_mismatch")
        }
        OAuthUserInfoEndpointNotFound => {
            ("invalid_provider", "user_info_endpoint_not_found")
        }
        OAuthMissingUserInfo => ("invalid_provider", "missing_user_info"),
        crate::AuthError::OAuthInvalidCode => ("invalid_provider", "token_response_error"),
        crate::AuthError::OAuthUserInfoUnavailable => {
            ("invalid_provider", "userinfo_response_error")
        }
        _ => (
            crate::axum::oauth_callback_error_code(error),
            "token_response_error",
        ),
    }
}

pub(in crate::sso::axum) fn callback_error_response(
    base: &str,
    error: &crate::AuthError,
) -> Response {
    match error {
        crate::AuthError::SsoUserResolutionRejected { code, message } => {
            crate::axum::oauth_redirect_error(base, code, message.as_deref())
        }
        crate::AuthError::SsoUserResolutionFailed => crate::axum::oauth_redirect_error(
            base,
            "SSO_USER_RESOLUTION_FAILED",
            Some("Unable to resolve the SSO user"),
        ),
        crate::AuthError::SsoAuthenticationConflict { code, message } => {
            crate::axum::oauth_redirect_error(base, code, Some(message))
        }
        crate::AuthError::SsoUserResolutionIdTokenRequired => crate::axum::oauth_redirect_error(
            base,
            "invalid_provider",
            Some("id_token_required_for_user_resolution"),
        ),
        _ => {
            let (code, description) = callback_error(error);
            crate::axum::oauth_redirect_error(base, code, Some(description))
        }
    }
}

pub(in crate::sso::axum) async fn success(
    service: &AuthService,
    headers: &HeaderMap,
    provider_id: &str,
    result: crate::OAuthCallbackResult,
) -> Response {
    let location = match HeaderValue::from_str(&result.redirect_url) {
        Ok(location) => location,
        Err(_) => {
            return support::error(
                axum::http::StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid callback URL",
            );
        }
    };
    let response = crate::axum::api_redirect(location);
    let response = match result.session.as_ref() {
        Some(session) => {
            crate::axum::http::with_bound_session_cookie(
                service,
                headers,
                &session.session.user.id,
                &session.token,
                Some(true),
                response,
            )
            .await
        }
        None => response,
    };
    let response = match result.session.as_ref() {
        Some(session) => {
            crate::axum::with_provider_account_cookie(
                service,
                headers,
                &session.session.user.id,
                provider_id,
                response,
            )
            .await
        }
        None => response,
    };
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(
            &service.plugin_cookie(service.oauth_state_cookie_name()),
            "",
            Some(0),
        ),
    )
}
