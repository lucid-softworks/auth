use super::response::no_store;
use crate::{AuthError, AxumPluginRoute, axum::http::auth_error};
use axum::{
    Extension,
    extract::Request,
    http::HeaderMap,
    middleware::Next,
    response::Response,
    routing::{get, post},
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Map;
use std::{collections::BTreeMap, sync::Arc};

use super::super::{
    OAuthCallbackContext, OAuthClientAction, OAuthProviderClient, OAuthProviderConfig,
    OAuthProviderStore,
};

mod client;
mod consent;
mod input;
mod key_material;
mod logout_validation;
pub(crate) mod registration;
mod registration_support;
pub(crate) mod validation;
pub(crate) mod validation_support;
mod wire;

use input::ClientMetadataInput;

#[derive(Clone)]
struct ManagementState {
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
}

async fn resolve_provider_client(
    state: &ManagementState,
    headers: &HeaderMap,
    client_id: &str,
) -> Result<Option<OAuthProviderClient>, super::super::OAuthProviderError> {
    super::client::resolve_client(&state.config, state.store.as_ref(), headers, client_id).await
}

pub(super) fn routes(
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
) -> Vec<AxumPluginRoute> {
    let state = ManagementState { config, store };
    vec![
        no_store_route("/oauth2/register", post(registration::register), &state),
        no_store_route("/oauth2/create-client", post(client::create_client), &state),
        route("/oauth2/get-client", get(client::get_client), &state),
        route(
            "/oauth2/public-client",
            get(client::get_public_client),
            &state,
        ),
        route(
            "/oauth2/public-client-prelogin",
            post(client::get_public_client_prelogin),
            &state,
        ),
        route("/oauth2/get-clients", get(client::list_clients), &state),
        route("/oauth2/update-client", post(client::update_client), &state),
        no_store_route(
            "/oauth2/client/rotate-secret",
            post(client::rotate_secret),
            &state,
        ),
        route("/oauth2/delete-client", post(client::delete_client), &state),
        route("/oauth2/get-consent", get(consent::get), &state),
        route("/oauth2/get-consents", get(consent::list), &state),
        route("/oauth2/update-consent", post(consent::update), &state),
        route("/oauth2/delete-consent", post(consent::delete), &state),
    ]
}

fn route(
    path: &'static str,
    method: axum::routing::MethodRouter,
    state: &ManagementState,
) -> AxumPluginRoute {
    AxumPluginRoute::new(path, method.layer(Extension(state.clone())))
}

fn no_store_route(
    path: &'static str,
    method: axum::routing::MethodRouter,
    state: &ManagementState,
) -> AxumPluginRoute {
    route(
        path,
        method.layer(axum::middleware::from_fn(add_no_store)),
        state,
    )
}

async fn add_no_store(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() == axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE {
        response
    } else {
        no_store(response)
    }
}

fn apply_update(client: &mut OAuthProviderClient, input: ClientMetadataInput) {
    if let Some(value) = input.redirect_uris {
        client.redirect_uris = value;
    }
    if let Some(value) = input.scope {
        client.scopes = Some(split_scopes(&value));
    }
    if let Some(value) = input.client_name {
        client.name = Some(value);
    }
    if let Some(value) = input.client_uri {
        client.uri = Some(value);
    }
    if let Some(value) = input.logo_uri {
        client.icon = Some(value);
    }
    if let Some(value) = input.contacts {
        client.contacts = Some(value);
    }
    if let Some(value) = input.tos_uri {
        client.tos = Some(value);
    }
    if let Some(value) = input.policy_uri {
        client.policy = Some(value);
    }
    if let Some(value) = input.software_id {
        client.software_id = Some(value);
    }
    if let Some(value) = input.software_version {
        client.software_version = Some(value);
    }
    if let Some(value) = input.software_statement {
        client.software_statement = Some(value);
    }
    if let Some(value) = input.post_logout_redirect_uris {
        client.post_logout_redirect_uris = Some(value);
    }
    if let Some(value) = input.backchannel_logout_uri {
        client.backchannel_logout_uri = Some(value);
    }
    if let Some(value) = input.backchannel_logout_session_required {
        client.backchannel_logout_session_required = Some(value);
    }
    if let Some(value) = input.application_type {
        client.application_type = Some(value);
    }
    if let Some(value) = input.grant_types {
        client.grant_types = Some(value);
    }
    if let Some(value) = input.response_types {
        client.response_types = Some(value);
    }
}

fn merged_client_metadata(
    client: &OAuthProviderClient,
    update: &ClientMetadataInput,
) -> ClientMetadataInput {
    let mut merged = ClientMetadataInput {
        redirect_uris: Some(client.redirect_uris.clone()),
        scope: client.scopes.as_ref().map(|scopes| scopes.join(" ")),
        client_name: client.name.clone(),
        client_uri: client.uri.clone(),
        logo_uri: client.icon.clone(),
        contacts: client.contacts.clone(),
        tos_uri: client.tos.clone(),
        policy_uri: client.policy.clone(),
        software_id: client.software_id.clone(),
        software_version: client.software_version.clone(),
        software_statement: client.software_statement.clone(),
        post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: client.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: client.backchannel_logout_session_required,
        token_endpoint_auth_method: client.token_endpoint_auth_method.clone(),
        application_type: client.application_type.clone(),
        jwks: client
            .jwks
            .as_ref()
            .and_then(|jwks| serde_json::from_str(jwks).ok()),
        jwks_uri: client.jwks_uri.clone(),
        grant_types: client.grant_types.clone(),
        response_types: client.response_types.clone(),
        require_pkce: client.require_pkce,
        dpop_bound_access_tokens: Some(client.dpop_bound_access_tokens),
        subject_type: client.subject_type.clone(),
        resources: None,
        extensions: Map::new(),
    };
    macro_rules! overlay {
        ($field:ident) => {
            if update.$field.is_some() {
                merged.$field.clone_from(&update.$field);
            }
        };
    }
    overlay!(redirect_uris);
    overlay!(scope);
    overlay!(client_name);
    overlay!(client_uri);
    overlay!(logo_uri);
    overlay!(contacts);
    overlay!(tos_uri);
    overlay!(policy_uri);
    overlay!(software_id);
    overlay!(software_version);
    overlay!(software_statement);
    overlay!(post_logout_redirect_uris);
    overlay!(backchannel_logout_uri);
    overlay!(backchannel_logout_session_required);
    overlay!(application_type);
    overlay!(grant_types);
    overlay!(response_types);
    merged
}

async fn owns_client(
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    session: &crate::SessionWithUser,
    context: &OAuthCallbackContext,
) -> bool {
    if let Some(user_id) = client.user_id.as_deref() {
        return user_id == session.user.id;
    }
    let Some(expected) = client.reference_id.as_deref() else {
        return false;
    };
    let Some(resolver) = &config.callbacks.client_reference else {
        return false;
    };
    matches!(resolver.resolve(context).await, Ok(Some(actual)) if actual == expected)
}

async fn authorize_client_action(
    config: &OAuthProviderConfig,
    action: OAuthClientAction,
    context: &OAuthCallbackContext,
) -> Result<(), Box<Response>> {
    let Some(callback) = &config.callbacks.client_privileges else {
        return Ok(());
    };
    match callback.authorize(action, context).await {
        Ok(Some(true)) => Ok(()),
        Ok(_) => Err(Box::new(auth_error(AuthError::Unauthorized))),
        Err(error) => Err(Box::new(auth_error(error))),
    }
}

async fn resolve_client_reference(
    config: &OAuthProviderConfig,
    context: &OAuthCallbackContext,
) -> Result<Option<String>, Box<Response>> {
    match &config.callbacks.client_reference {
        Some(callback) => callback
            .resolve(context)
            .await
            .map_err(auth_error)
            .map_err(Box::new),
        None => Ok(None),
    }
}

fn callback_context(
    headers: &HeaderMap,
    session: Option<&crate::SessionWithUser>,
    scopes: Option<&str>,
) -> OAuthCallbackContext {
    OAuthCallbackContext {
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>(),
        user: session.and_then(|session| serde_json::to_value(&session.user).ok()),
        session: session.and_then(|session| serde_json::to_value(&session.session).ok()),
        scopes: scopes.map(split_scopes).unwrap_or_default(),
    }
}

fn split_scopes(scopes: &str) -> Vec<String> {
    scopes.split_whitespace().map(str::to_owned).collect()
}

fn second_precision_now() -> DateTime<Utc> {
    Utc.timestamp_opt(Utc::now().timestamp(), 0)
        .single()
        .unwrap_or_else(Utc::now)
}
