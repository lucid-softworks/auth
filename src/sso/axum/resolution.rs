use crate::{AuthError, AuthService, OAuthTokens, OAuthUserInfo, SsoPlugin, SsoProvider};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) struct FinishInput {
    pub provider: SsoProvider,
    pub provider_reference: crate::SsoProviderReference,
    pub resolution_input: crate::SsoUserResolutionInput,
    pub tokens: OAuthTokens,
    pub user_info: OAuthUserInfo,
    pub state: crate::service::OAuthState,
    pub override_user_info: bool,
    pub user_agent: Option<String>,
}

pub(super) async fn finish(
    service: &AuthService,
    plugin: &SsoPlugin,
    input: FinishInput,
) -> Result<crate::OAuthCallbackResult, AuthError> {
    if !plugin.has_user_resolver() {
        return service
            .finish_sso_sign_in_with_tokens(
                &input.provider.provider_id,
                input.tokens,
                input.user_info,
                input.state,
                plugin.options().disable_implicit_sign_up,
                input.override_user_info,
                input.user_agent,
            )
            .await;
    }
    let store = service.database_store();
    let service = service.clone();
    let plugin = plugin.clone();
    crate::run_database_transaction(store.as_ref(), move |transaction| {
        Box::pin(async move {
            let current = plugin
                .find_auth_provider(&input.provider.provider_id)
                .await
                .map_err(|error| AuthError::Storage(error.to_string()))?
                .ok_or_else(provider_changed)?;
            if !input.provider_reference.is_current(&current) {
                return Err(provider_changed());
            }
            let resolution = plugin
                .resolve_user(input.resolution_input, transaction)
                .await?;
            let selected_user = match resolution {
                crate::SsoUserResolution::Continue => None,
                crate::SsoUserResolution::Link { user_id, profile } => {
                    Some(crate::service::OAuthSelectedUser {
                        user_id,
                        update_profile: profile == crate::SsoUserProfilePolicy::Update,
                    })
                }
                crate::SsoUserResolution::Reject { code, message } => {
                    return Err(AuthError::SsoUserResolutionRejected { code, message });
                }
            };
            service
                .finish_sso_sign_in_with_resolution(
                    &input.provider.provider_id,
                    input.tokens,
                    input.user_info,
                    input.state,
                    plugin.options().disable_implicit_sign_up,
                    input.override_user_info,
                    selected_user,
                    true,
                    input.user_agent,
                )
                .await
        })
    })
    .await
}

pub(super) fn oidc_input(
    plugin: &SsoPlugin,
    provider: &SsoProvider,
    reference: crate::SsoProviderReference,
    tokens: &OAuthTokens,
    user_info: &OAuthUserInfo,
) -> Result<crate::SsoUserResolutionInput, AuthError> {
    let verified_id_token_claims = if plugin.has_user_resolver() {
        tokens
            .id_token
            .as_deref()
            .and_then(jwt_payload)
            .ok_or(AuthError::SsoUserResolutionIdTokenRequired)?
    } else {
        serde_json::Map::new()
    };
    Ok(crate::SsoUserResolutionInput::Oidc {
        provider_id: provider.provider_id.clone(),
        account_issuer: user_info.issuer.clone(),
        account_id: user_info.account_id.clone(),
        provider_user: provider_user(user_info),
        provider_claims: user_info.profile.clone(),
        verified_id_token_claims,
        provider_reference: reference,
    })
}

pub(super) fn saml_input(
    provider: &SsoProvider,
    reference: crate::SsoProviderReference,
    user_info: &OAuthUserInfo,
) -> crate::SsoUserResolutionInput {
    crate::SsoUserResolutionInput::Saml {
        provider_id: provider.provider_id.clone(),
        account_issuer: user_info.issuer.clone(),
        account_id: user_info.account_id.clone(),
        provider_user: provider_user(user_info),
        provider_attributes: user_info.profile.clone(),
        provider_reference: reference,
    }
}

fn provider_user(user_info: &OAuthUserInfo) -> crate::SsoProviderUserProfile {
    crate::SsoProviderUserProfile {
        email: user_info.email.clone(),
        email_verified: user_info.email_verified,
        name: user_info.name.clone(),
        image: user_info.image.clone(),
        additional_fields: user_info.additional_fields.clone(),
    }
}

fn jwt_payload(token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let encoded = token.split('.').nth(1)?;
    serde_json::from_slice::<serde_json::Value>(&URL_SAFE_NO_PAD.decode(encoded).ok()?)
        .ok()?
        .as_object()
        .cloned()
}

fn provider_changed() -> AuthError {
    AuthError::SsoAuthenticationConflict {
        code: "SSO_PROVIDER_CHANGED",
        message: "SSO provider changed while account linking was in progress",
    }
}
