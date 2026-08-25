use axum::{http::HeaderMap, response::Response};

use crate::{
    AuthService, OAuthProviderError,
    oauth_provider::{
        OAuthProviderClient, OAuthProviderConfig, OAuthProviderStore,
        authorization::OAuthAuthorizationQuery,
    },
};

use super::{
    claims,
    helpers::{split_scopes, validate_pkce, validate_resources},
    validation::{Validation, respond},
};

pub(super) async fn validate(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &mut OAuthAuthorizationQuery,
    client: &OAuthProviderClient,
) -> Result<Validation<Vec<String>>, OAuthProviderError> {
    let scopes = requested_scopes(config, client, query);
    if let Some(description) = invalid_scope_description(config, client, &scopes) {
        return respond(
            service,
            config,
            store,
            headers,
            query,
            "invalid_scope",
            &description,
        )
        .await;
    }
    query.scope = Some(scopes.join(" "));
    if let Some(response) = validate_claims(service, config, store, headers, query, &scopes).await?
    {
        return Ok(Validation::Respond(response));
    }
    if let Some(response) =
        validate_protocol(service, config, store, headers, query, client, &scopes).await?
    {
        return Ok(Validation::Respond(response));
    }
    Ok(Validation::Ready(scopes))
}

async fn validate_claims(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    scopes: &[String],
) -> Result<Option<Response>, OAuthProviderError> {
    let error = if query.claims.is_some() && !scopes.iter().any(|scope| scope == "openid") {
        Some((
            "invalid_request",
            "openid scope must be requested when using the claims parameter",
        ))
    } else if query
        .claims
        .as_ref()
        .is_some_and(|request| !claims::is_valid_request(request))
    {
        Some((
            "invalid_request",
            "claims must be a valid Claims request object",
        ))
    } else if query
        .claims
        .as_ref()
        .is_some_and(|request| !claims::can_satisfy_essential_acr(request))
    {
        Some(("access_denied", "essential acr requirement cannot be met"))
    } else {
        None
    };
    respond_to_error(service, config, store, headers, query, error).await
}

async fn validate_protocol(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    client: &OAuthProviderClient,
    scopes: &[String],
) -> Result<Option<Response>, OAuthProviderError> {
    let error = if let Err(description) = validate_pkce(client, query, scopes) {
        Some(("invalid_request", description.to_owned()))
    } else if let Err(error) =
        validate_resources(config, store, client, &query.resource, scopes).await
    {
        Some((
            error.code(),
            super::super::response::description(&error).to_owned(),
        ))
    } else {
        None
    };
    respond_to_owned_error(service, config, store, headers, query, error).await
}

async fn respond_to_error(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    error: Option<(&str, &str)>,
) -> Result<Option<Response>, OAuthProviderError> {
    respond_to_owned_error(
        service,
        config,
        store,
        headers,
        query,
        error.map(|(code, description)| (code, description.to_owned())),
    )
    .await
}

async fn respond_to_owned_error(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    query: &OAuthAuthorizationQuery,
    error: Option<(&str, String)>,
) -> Result<Option<Response>, OAuthProviderError> {
    let Some((code, description)) = error else {
        return Ok(None);
    };
    match respond::<()>(service, config, store, headers, query, code, &description).await? {
        Validation::Respond(response) => Ok(Some(response)),
        Validation::Ready(()) => Ok(None),
    }
}

fn requested_scopes(
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    query: &OAuthAuthorizationQuery,
) -> Vec<String> {
    query.scope.as_deref().map(split_scopes).unwrap_or_else(|| {
        client
            .scopes
            .clone()
            .unwrap_or_else(|| config.scopes.clone())
    })
}

fn invalid_scope_description(
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    scopes: &[String],
) -> Option<String> {
    let allowed = client.scopes.as_ref().unwrap_or(&config.scopes);
    let invalid = scopes
        .iter()
        .filter(|scope| !allowed.contains(scope))
        .cloned()
        .collect::<Vec<_>>();
    (!invalid.is_empty())
        .then(|| format!("The following scopes are invalid: {}", invalid.join(", ")))
}
