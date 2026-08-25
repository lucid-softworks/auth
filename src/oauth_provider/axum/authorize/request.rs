use axum::http::HeaderMap;

use crate::{
    OAuthProviderError,
    oauth_provider::{
        OAuthCallbackContext, OAuthProviderConfig, authorization::OAuthAuthorizationQuery,
    },
};

use super::helpers::storage_error;

pub(super) async fn prepare_request(
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    query: &mut OAuthAuthorizationQuery,
) -> Result<(), OAuthProviderError> {
    validate_request_object_pair(query)?;
    let Some(request_uri) = query.request_uri.clone() else {
        return Ok(());
    };
    let client_id = query
        .client_id
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| OAuthProviderError::InvalidRequest("client_id is required".into()))?;
    let resolver = config
        .callbacks
        .request_uri_resolver
        .as_ref()
        .ok_or_else(|| {
            OAuthProviderError::RequestUriNotSupported("request_uri not supported".into())
        })?;
    let pairs = resolver
        .resolve(&request_uri, &client_id, &callback_context(headers))
        .await
        .map_err(storage_error)?
        .ok_or_else(|| {
            OAuthProviderError::InvalidRequestUri("request_uri is invalid or expired".into())
        })?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(pairs);
    let input: super::AuthorizationInput = serde_urlencoded::from_str(&serializer.finish())
        .map_err(|_| {
            OAuthProviderError::InvalidRequestUri("request_uri is invalid or expired".into())
        })?;
    *query = input.into_query()?;
    query.client_id = Some(client_id);
    Ok(())
}

fn validate_request_object_pair(query: &OAuthAuthorizationQuery) -> Result<(), OAuthProviderError> {
    if query.request.is_some() && query.request_uri.is_some() {
        return Err(OAuthProviderError::InvalidRequest(
            "request and request_uri cannot be used together".into(),
        ));
    }
    if query.request.is_some() {
        return Err(OAuthProviderError::RequestNotSupported(
            "request object not supported".into(),
        ));
    }
    Ok(())
}

fn callback_context(headers: &HeaderMap) -> OAuthCallbackContext {
    OAuthCallbackContext {
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect(),
        user: None,
        session: None,
        scopes: Vec::new(),
    }
}
