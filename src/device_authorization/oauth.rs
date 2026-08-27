use super::{DEVICE_CODE_GRANT_TYPE, DeviceAuthorizationStore};
#[cfg(feature = "axum")]
use super::{
    DeviceAuthorizationConfig, DeviceAuthorizationRequest, DeviceCode, DeviceCodeOwner,
    DeviceCodeStatus, generate_device_authorization,
};
#[cfg(feature = "axum")]
use crate::{
    OAuthExtensionGrantInput, OAuthProviderApi, OAuthProviderApiAuthenticationRequest,
    OAuthProviderApiTokenIssueInput, OAuthProviderAuthenticatedClient, OAuthProviderError,
};
use crate::{OAuthProviderExtension, OAuthProviderMetadataDocument};
use async_trait::async_trait;
#[cfg(feature = "axum")]
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[cfg(feature = "axum")]
mod parameters;
#[cfg(feature = "axum")]
use parameters::{
    has_client_authentication, header_parameters, nonempty_values, singleton, split_scopes,
    string_parameters,
};

#[derive(Clone)]
pub(crate) struct OAuthDeviceAuthorizationExtension {
    #[cfg_attr(not(feature = "axum"), allow(dead_code))]
    store: Arc<dyn DeviceAuthorizationStore>,
}

impl OAuthDeviceAuthorizationExtension {
    pub(crate) fn new(store: Arc<dyn DeviceAuthorizationStore>) -> Self {
        Self { store }
    }
}

#[cfg(feature = "axum")]
pub(crate) async fn issue_code(
    service: Arc<crate::AuthService>,
    config: Arc<DeviceAuthorizationConfig>,
    store: Arc<dyn DeviceAuthorizationStore>,
    headers: axum::http::HeaderMap,
    input: super::axum::request::CodeInput,
) -> axum::response::Response {
    match issue_code_result(service, config, store, &headers, input).await {
        Ok(response) => response,
        Err(error) => crate::oauth_provider::axum::response::oauth_error(&error),
    }
}

#[cfg(feature = "axum")]
async fn issue_code_result(
    service: Arc<crate::AuthService>,
    config: Arc<DeviceAuthorizationConfig>,
    store: Arc<dyn DeviceAuthorizationStore>,
    headers: &axum::http::HeaderMap,
    input: super::axum::request::CodeInput,
) -> Result<axum::response::Response, OAuthProviderError> {
    use axum::response::IntoResponse as _;

    let parameters = string_parameters(&input.parameters)?;
    let base_url = super::axum::uri::request_base_url(&service, headers);
    let provider = request_provider(service.clone(), headers, &base_url, parameters.clone())?;
    let scopes = split_scopes(input.scope.as_deref());
    if let Some(client_id) = input.client_id.as_deref()
        && !has_client_authentication(headers, &parameters)
        && provider.get_client(client_id).await?.is_none()
    {
        return Err(OAuthProviderError::InvalidClient(
            "Invalid client ID".into(),
        ));
    }
    let authenticated = provider
        .authenticate_client(OAuthProviderApiAuthenticationRequest {
            scopes: scopes.clone(),
            require_credentials: false,
        })
        .await?;
    if input
        .client_id
        .as_deref()
        .is_some_and(|client_id| client_id != authenticated.client_id)
    {
        return Err(OAuthProviderError::InvalidClient(
            "Client ID mismatch".into(),
        ));
    }
    let resources = nonempty_values(&parameters, "resource");
    provider
        .validate_resource_policy(&authenticated.client, &scopes, resources.as_deref())
        .await?;
    let user_id = input.user_id.clone();
    let generated = generate_device_authorization(
        &service,
        store.as_ref(),
        &config,
        &base_url,
        DeviceAuthorizationRequest {
            client_id: authenticated.client_id.clone(),
            user_id,
            scope: input.scope.map(|_| scopes.join(" ")),
            resources,
            oauth_client_id: Some(authenticated.client_id),
        },
    )
    .await
    .map_err(|error| OAuthProviderError::ServerError(error.to_string()))?;
    Ok(super::axum::error::no_store(
        axum::Json(json!({
            "device_code": generated.record.device_code,
            "user_code": generated.record.user_code,
            "verification_uri": generated.verification_uri,
            "verification_uri_complete": generated.verification_uri_complete,
            "expires_in": generated.expires_in,
            "interval": generated.interval,
        }))
        .into_response(),
    ))
}

#[cfg(feature = "axum")]
fn request_provider(
    service: Arc<crate::AuthService>,
    headers: &axum::http::HeaderMap,
    base_url: &str,
    parameters: std::collections::BTreeMap<String, Vec<String>>,
) -> Result<OAuthProviderApi, OAuthProviderError> {
    let provider_plugin = service.oauth_provider_plugin().ok_or_else(|| {
        OAuthProviderError::ServerError("OAuth Provider plugin is unavailable".into())
    })?;
    provider_plugin.provider_api(
        service.clone(),
        crate::OAuthProviderApiRequest {
            endpoint: format!("{}/device/code", base_url.trim_end_matches('/')),
            headers: header_parameters(headers),
            parameters,
        },
        Some(DEVICE_CODE_GRANT_TYPE.into()),
    )
}

#[async_trait]
impl OAuthProviderExtension for OAuthDeviceAuthorizationExtension {
    fn grant_types(&self) -> Vec<String> {
        vec![DEVICE_CODE_GRANT_TYPE.into()]
    }

    fn server_metadata(
        &self,
        _document: OAuthProviderMetadataDocument,
        base: &Map<String, Value>,
    ) -> Map<String, Value> {
        let Some(issuer) = base.get("issuer").and_then(Value::as_str) else {
            return Map::new();
        };
        Map::from_iter([(
            "device_authorization_endpoint".into(),
            json!(format!("{}/device/code", issuer.trim_end_matches('/'))),
        )])
    }

    #[cfg(feature = "axum")]
    async fn token_grant(
        &self,
        input: &OAuthExtensionGrantInput,
    ) -> Result<Value, OAuthProviderError> {
        exchange_device_code(self.store.as_ref(), input).await
    }
}

#[cfg(feature = "axum")]
struct AuthorizedRedemption {
    record: DeviceCode,
    authenticated: OAuthProviderAuthenticatedClient,
    scopes: Vec<String>,
}

#[cfg(feature = "axum")]
async fn exchange_device_code(
    store: &dyn DeviceAuthorizationStore,
    input: &OAuthExtensionGrantInput,
) -> Result<Value, OAuthProviderError> {
    let authorized = authorize_redemption(store, input).await?;
    poll(store, &authorized.record).await?;
    let effective_resources = prepare_redemption(input, &authorized).await?;
    let consumed = store
        .consume_approved_device_code(
            &authorized.record.id,
            DeviceCodeOwner::OAuthClientId(authorized.authenticated.client_id.clone()),
        )
        .await
        .map_err(server)?
        .ok_or_else(invalid_device_code)?;

    let mut issue =
        OAuthProviderApiTokenIssueInput::new(authorized.authenticated.client, authorized.scopes);
    issue.verification_value = serde_json::to_value(&consumed).ok();
    issue.user_id = consumed.user_id;
    issue.resources = effective_resources;
    issue.original_resources = authorized.record.resources;
    issue.confirmation = authorized.authenticated.confirmation;
    input.provider.issue_tokens(issue).await
}

#[cfg(feature = "axum")]
async fn authorize_redemption(
    store: &dyn DeviceAuthorizationStore,
    input: &OAuthExtensionGrantInput,
) -> Result<AuthorizedRedemption, OAuthProviderError> {
    let device_code = singleton(&input.parameters, "device_code")?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| OAuthProviderError::InvalidRequest("device_code is required".into()))?;
    let record = store
        .find_device_code(device_code)
        .await
        .map_err(server)?
        .ok_or_else(invalid_device_code)?;
    let oauth_client_id = record
        .oauth_client_id
        .as_deref()
        .ok_or_else(|| OAuthProviderError::InvalidGrant("invalid device code".into()))?;
    if singleton(&input.parameters, "client_id")?
        .is_some_and(|client_id| client_id != oauth_client_id)
    {
        return Err(client_id_mismatch());
    }
    let scopes = split_scopes(record.scope.as_deref());
    let authenticated = input
        .provider
        .authenticate_client(OAuthProviderApiAuthenticationRequest {
            scopes: scopes.clone(),
            require_credentials: false,
        })
        .await?;
    if oauth_client_id != authenticated.client_id {
        return Err(client_id_mismatch());
    }
    Ok(AuthorizedRedemption {
        record,
        authenticated,
        scopes,
    })
}

#[cfg(feature = "axum")]
async fn prepare_redemption(
    input: &OAuthExtensionGrantInput,
    authorized: &AuthorizedRedemption,
) -> Result<Option<Vec<String>>, OAuthProviderError> {
    let requested = nonempty_values(&input.parameters, "resource");
    if requested.as_deref().is_some_and(|requested| {
        requested.iter().any(|resource| {
            !authorized
                .record
                .resources
                .as_deref()
                .is_some_and(|allowed| allowed.contains(resource))
        })
    }) {
        return Err(OAuthProviderError::InvalidTarget(
            "Requested resource was not authorized by the user".into(),
        ));
    }
    let effective = requested.or_else(|| authorized.record.resources.clone());
    input
        .provider
        .validate_resource_policy(
            &authorized.authenticated.client,
            &authorized.scopes,
            effective.as_deref(),
        )
        .await?;
    let user_id = authorized
        .record
        .user_id
        .as_deref()
        .ok_or_else(|| OAuthProviderError::ServerError("Invalid device code status".into()))?;
    if input.provider.load_user(user_id).await?.is_none() {
        return Err(OAuthProviderError::ServerError("User not found".into()));
    }
    Ok(effective)
}

#[cfg(feature = "axum")]
async fn poll(
    store: &dyn DeviceAuthorizationStore,
    record: &DeviceCode,
) -> Result<(), OAuthProviderError> {
    let now = Utc::now();
    if record.last_polled_at.is_some_and(|last| {
        record.polling_interval.is_some_and(|interval| {
            interval != 0.0
                && ((now.timestamp_millis() - last.timestamp_millis()) as f64) < interval
        })
    }) {
        return Err(OAuthProviderError::SlowDown(
            "Polling too frequently".into(),
        ));
    }
    store
        .update_last_polled_at(&record.id, now)
        .await
        .map_err(server)?;
    if record.expires_at < now {
        store.delete_device_code(&record.id).await.map_err(server)?;
        return Err(OAuthProviderError::ExpiredToken(
            "Device code has expired".into(),
        ));
    }
    match record.status {
        DeviceCodeStatus::Pending => Err(OAuthProviderError::AuthorizationPending(
            "Authorization pending".into(),
        )),
        DeviceCodeStatus::Denied => {
            store.delete_device_code(&record.id).await.map_err(server)?;
            Err(OAuthProviderError::AccessDenied("Access denied".into()))
        }
        DeviceCodeStatus::Approved if record.user_id.is_some() => Ok(()),
        DeviceCodeStatus::Approved => Err(OAuthProviderError::ServerError(
            "Invalid device code status".into(),
        )),
    }
}

#[cfg(feature = "axum")]
fn invalid_device_code() -> OAuthProviderError {
    OAuthProviderError::InvalidGrant("Invalid device code".into())
}

#[cfg(feature = "axum")]
fn client_id_mismatch() -> OAuthProviderError {
    OAuthProviderError::InvalidGrant("Client ID mismatch".into())
}

#[cfg(feature = "axum")]
fn server(error: crate::AuthError) -> OAuthProviderError {
    OAuthProviderError::ServerError(error.to_string())
}
