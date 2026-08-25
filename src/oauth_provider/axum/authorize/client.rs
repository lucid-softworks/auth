use super::helpers::{client_allows_grant, registered_redirect_matches};
use super::validation::{Validation, respond};
use crate::AuthService;
use crate::oauth_provider::{
    OAuthProviderClient, OAuthProviderConfig, OAuthProviderError, OAuthProviderStore,
    authorization::OAuthAuthorizationQuery,
};
use axum::http::HeaderMap;

pub(super) async fn resolve_client(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
) -> Result<Validation<OAuthProviderClient>, OAuthProviderError> {
    let Some(client_id) = query.client_id.as_deref().filter(|value| !value.is_empty()) else {
        return respond(
            service,
            config,
            store,
            headers,
            query,
            "invalid_request",
            "client_id is required",
        )
        .await;
    };
    let Some(client) =
        super::super::client::resolve_client(config, store, headers, client_id).await?
    else {
        return respond(
            service,
            config,
            store,
            headers,
            query,
            "invalid_client",
            "client_id is required",
        )
        .await;
    };
    validate_client(service, config, store, headers, query, client).await
}

async fn validate_client(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    client: OAuthProviderClient,
) -> Result<Validation<OAuthProviderClient>, OAuthProviderError> {
    let error = if client.disabled {
        Some(("client_disabled", "client is disabled"))
    } else if !registered_redirect_matches(
        &client.redirect_uris,
        query.redirect_uri.as_deref().unwrap_or_default(),
    ) {
        Some(("invalid_redirect", "invalid redirect uri"))
    } else if !client_allows_grant(&client, "authorization_code") {
        Some((
            "unauthorized_client",
            "client is not authorized to use the authorization_code grant",
        ))
    } else {
        None
    };
    match error {
        Some((code, description)) => {
            respond(service, config, store, headers, query, code, description).await
        }
        None => Ok(Validation::Ready(client)),
    }
}
