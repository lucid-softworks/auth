use crate::{AuthService, AxumPluginRoute};
use axum::{
    Extension,
    extract::Query,
    http::HeaderMap,
    response::Response,
    routing::{MethodRouter, get, post},
};
use serde::Deserialize;
use std::{convert::Infallible, sync::Arc};

use super::{
    super::{OAuthProviderConfig, OAuthProviderStore, authorization::OAuthAuthorizationQuery},
    metadata::{issuer, provider_issuer},
    response::oauth_error,
};
use crate::OAuthProviderError;
use crate::oauth_provider::axum::body::FormOnly;

mod claims;
mod client;
mod constraints;
mod flow;
mod helpers;
mod prompt;
mod request;
mod stages;
mod syntax;
mod validation;

use helpers::{redirect, registered_redirect_matches, verified_signed_query};

pub(super) fn routes(
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/oauth2/authorize",
            with_extensions(
                get(authorize_get).post(authorize_post),
                config.clone(),
                store.clone(),
            ),
        ),
        AxumPluginRoute::new(
            "/oauth2/consent",
            with_extensions(post(flow::consent), config.clone(), store.clone()),
        ),
        AxumPluginRoute::new(
            "/oauth2/continue",
            with_extensions(post(flow::continue_authorization), config, store),
        ),
    ]
}

fn with_extensions(
    route: MethodRouter,
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
) -> MethodRouter {
    route
        .layer::<_, Infallible>(Extension(store))
        .layer::<_, Infallible>(Extension(config))
}

#[derive(Debug, Clone, Default, Deserialize)]
struct AuthorizationInput {
    response_type: Option<String>,
    request: Option<String>,
    request_uri: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    prompt: Option<String>,
    display: Option<String>,
    ui_locales: Option<String>,
    max_age: Option<u64>,
    acr_values: Option<String>,
    login_hint: Option<String>,
    id_token_hint: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    claims: Option<String>,
    dpop_jkt: Option<String>,
    #[serde(default)]
    resource: Vec<String>,
}

impl AuthorizationInput {
    fn into_query(self) -> Result<OAuthAuthorizationQuery, OAuthProviderError> {
        let claims = self
            .claims
            .map(|claims| {
                serde_json::from_str(&claims).map_err(|_| {
                    OAuthProviderError::InvalidRequest(
                        "claims must be a valid Claims request object".into(),
                    )
                })
            })
            .transpose()?;
        Ok(OAuthAuthorizationQuery {
            response_type: self.response_type,
            request: self.request,
            request_uri: self.request_uri,
            redirect_uri: self.redirect_uri,
            scope: self.scope,
            state: self.state,
            client_id: self.client_id,
            prompt: self.prompt,
            display: self.display,
            ui_locales: self.ui_locales,
            max_age: self.max_age,
            acr_values: self.acr_values,
            login_hint: self.login_hint,
            id_token_hint: self.id_token_hint,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            nonce: self.nonce,
            claims,
            dpop_jkt: self.dpop_jkt,
            resource: self.resource,
        })
    }

    fn redirect_query(&self) -> OAuthAuthorizationQuery {
        OAuthAuthorizationQuery {
            redirect_uri: self.redirect_uri.clone(),
            state: self.state.clone(),
            client_id: self.client_id.clone(),
            ..OAuthAuthorizationQuery::default()
        }
    }
}

async fn authorize_get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    headers: HeaderMap,
    Query(input): Query<AuthorizationInput>,
) -> Response {
    authorize(service, config, store, headers, input).await
}

async fn authorize_post(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    headers: HeaderMap,
    FormOnly(input): FormOnly<AuthorizationInput>,
) -> Response {
    authorize(service, config, store, headers, input).await
}

async fn authorize(
    service: Arc<AuthService>,
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
    headers: HeaderMap,
    input: AuthorizationInput,
) -> Response {
    let redirect_query = input.redirect_query();
    let query = match input.into_query() {
        Ok(query) => query,
        Err(error) => {
            return match redirect_error(
                &service,
                &config,
                store.as_ref(),
                &headers,
                &redirect_query,
                error.code(),
                super::response::description(&error),
            )
            .await
            {
                Ok(response) => response,
                Err(error) => oauth_error(&error),
            };
        }
    };
    match validation::authorize_validated(
        &service,
        &config,
        store.as_ref(),
        &headers,
        query,
        stages::AuthorizationStageState::default(),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => oauth_error(&error),
    }
}

pub(super) async fn redirect_error(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    code: &str,
    description: &str,
) -> Result<Response, OAuthProviderError> {
    let client = match query.client_id.as_deref() {
        Some(client_id) => super::client::resolve_client(config, store, headers, client_id).await?,
        None => None,
    };
    let trusted_redirect = client.filter(|client| !client.disabled).and_then(|client| {
        query
            .redirect_uri
            .as_deref()
            .filter(|redirect_uri| registered_redirect_matches(&client.redirect_uris, redirect_uri))
    });
    let error_base_url = issuer(service, headers);
    let response_issuer = provider_issuer(service, headers, config);
    let mut location = match trusted_redirect {
        Some(redirect_uri) => url::Url::parse(redirect_uri),
        None => url::Url::parse(&format!("{error_base_url}/error")),
    }
    .map_err(|_| OAuthProviderError::ServerError("invalid provider error URL".into()))?;
    location
        .query_pairs_mut()
        .append_pair("error", code)
        .append_pair("error_description", description);
    if trusted_redirect.is_some() {
        location
            .query_pairs_mut()
            .append_pair("iss", &response_issuer);
        if let Some(state) = &query.state {
            location.query_pairs_mut().append_pair("state", state);
        }
    }
    Ok(redirect(headers, location.as_str()))
}

pub(super) fn verify_oauth_query_signature(service: &AuthService, raw: &str) -> bool {
    verified_signed_query(service, raw).is_ok()
}
