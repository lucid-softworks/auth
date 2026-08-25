use super::super::{
    OAuthCallbackContext, OAuthProviderClient, OAuthProviderConfig, OAuthProviderError,
    OAuthProviderStore,
};
use axum::http::HeaderMap;
use std::collections::BTreeMap;

pub(super) async fn resolve_client(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    client_id: &str,
) -> Result<Option<OAuthProviderClient>, OAuthProviderError> {
    let stored = store
        .find_oauth_client(client_id)
        .await
        .map_err(|error| OAuthProviderError::ServerError(error.to_string()))?;
    if stored
        .as_ref()
        .is_some_and(|client| client.client_discovery_id.is_none())
    {
        return Ok(stored);
    }
    resolve_discovered_client(config, headers, client_id, stored.as_ref()).await
}

async fn resolve_discovered_client(
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    client_id: &str,
    stored_client: Option<&OAuthProviderClient>,
) -> Result<Option<OAuthProviderClient>, OAuthProviderError> {
    let context = OAuthCallbackContext {
        headers: header_context(headers),
        user: None,
        session: None,
        scopes: Vec::new(),
    };
    let discovery_id = stored_client.and_then(|client| client.client_discovery_id.as_deref());
    for extension in &config.extensions {
        let discovery_ids = extension.client_discovery_ids();
        if discovery_ids.is_empty()
            || discovery_id.is_some_and(|id| !discovery_ids.iter().any(|value| value == id))
        {
            continue;
        }
        let client = extension
            .discover_client(client_id, stored_client, &context)
            .await
            .map_err(|error| OAuthProviderError::ServerError(error.to_string()))?;
        if let Some(client) = client {
            if client.client_id != client_id {
                return Err(OAuthProviderError::InvalidClient(
                    "discovered client_id mismatch".into(),
                ));
            }
            return Ok(Some(client));
        }
    }
    Ok(None)
}

fn header_context(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}
