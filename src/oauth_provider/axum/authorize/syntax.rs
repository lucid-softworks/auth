use axum::http::HeaderMap;

use crate::{
    AuthService, OAuthProviderError,
    oauth_provider::{
        OAuthProviderConfig, OAuthProviderStore, authorization::OAuthAuthorizationQuery,
    },
};

use super::{prompt, redirect_error, validation::Validation};

pub(super) async fn prepare(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    mut query: OAuthAuthorizationQuery,
) -> Result<Validation<(OAuthAuthorizationQuery, Vec<String>)>, OAuthProviderError> {
    if let Err(error) = super::request::prepare_request(config, headers, &mut query).await {
        return redirect(
            service,
            config,
            store,
            headers,
            &query,
            error.code(),
            super::super::response::description(&error),
        )
        .await;
    }
    let prompts = match prompt::parse(query.prompt.as_deref()) {
        Ok(prompts) => prompts,
        Err(description) => {
            return redirect(
                service,
                config,
                store,
                headers,
                &query,
                "invalid_request",
                &description,
            )
            .await;
        }
    };
    if query.response_type.is_none() {
        return redirect(
            service,
            config,
            store,
            headers,
            &query,
            "invalid_request",
            "response_type is required",
        )
        .await;
    }
    if prompts.iter().any(|value| value == "select_account") && config.select_account_page.is_none()
    {
        return provider_error(
            service,
            config,
            store,
            headers,
            "unsupported_prompt_select_account",
            "unsupported prompt type",
        )
        .await;
    }
    if query.response_type.as_deref() != Some("code") {
        return provider_error(
            service,
            config,
            store,
            headers,
            "unsupported_response_type",
            "unsupported response type",
        )
        .await;
    }
    Ok(Validation::Ready((query, prompts)))
}

#[allow(clippy::too_many_arguments)]
async fn redirect<T>(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    code: &str,
    description: &str,
) -> Result<Validation<T>, OAuthProviderError> {
    redirect_error(service, config, store, headers, query, code, description)
        .await
        .map(Validation::Respond)
}

async fn provider_error<T>(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    code: &str,
    description: &str,
) -> Result<Validation<T>, OAuthProviderError> {
    redirect(
        service,
        config,
        store,
        headers,
        &OAuthAuthorizationQuery::default(),
        code,
        description,
    )
    .await
}
