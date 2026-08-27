use super::{
    client::resolve_client,
    metadata::{issuer, provider_issuer},
    response::{empty_no_store, no_store, oauth_error},
};
use crate::{
    AuthError, AuthService, AxumPluginRoute, JwtAdapterContext, JwtProtectedHeader,
    JwtSigningOverrides,
};
use axum::{
    Extension, Json,
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use url::Url;

use super::super::{
    DEFAULT_DPOP_ALGORITHMS, OAuthCallbackContext, OAuthClaimTarget,
    OAuthExtensionClientAuthentication, OAuthExtensionClientAuthenticationInput,
    OAuthExtensionGrantInput, OAuthProviderAccessToken, OAuthProviderClient,
    OAuthProviderClientAssertion, OAuthProviderConfig, OAuthProviderError, OAuthProviderExtension,
    OAuthProviderRefreshToken, OAuthProviderResource, OAuthProviderStore, OAuthRefreshRotation,
    OAuthRefreshRotationOutcome, OAuthStoredTokenType, OAuthTokenIssuance,
    authorization::OAuthAuthorizationCodePayload,
    crypto::{
        apply_token_prefix, client_assertion_id, decrypt_client_secret, hash_token, random_letters,
        store_token, strip_token_prefix, verify_client_secret, verify_s256_pkce,
    },
    expiration,
};

const MAX_BODY_BYTES: usize = 64 * 1024;
const PRIVATE_KEY_JWT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

pub(super) fn routes(
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/oauth2/token",
            endpoint_layers(post(token_endpoint), config.clone(), store.clone()),
        ),
        AxumPluginRoute::new(
            "/oauth2/introspect",
            endpoint_layers(post(introspection_endpoint), config.clone(), store.clone()),
        ),
        AxumPluginRoute::new(
            "/oauth2/revoke",
            endpoint_layers(post(revocation_endpoint), config.clone(), store.clone()),
        ),
        AxumPluginRoute::new(
            "/oauth2/userinfo",
            endpoint_layers(get(userinfo_get).post(userinfo_post), config, store),
        ),
    ]
}

fn endpoint_layers(
    route: axum::routing::MethodRouter,
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
) -> axum::routing::MethodRouter {
    route
        .layer::<_, std::convert::Infallible>(Extension(config))
        .layer::<_, std::convert::Infallible>(Extension(store))
}

include!("token/parameters.rs");
include!("token/request.rs");
include!("token/client_assertion_jwks.rs");
include!("token/client_assertion.rs");
include!("token/client_assertion_tests.rs");
include!("token/grant_authorization_code.rs");
include!("token/grant_other.rs");
include!("token/issue.rs");
include!("token/resource_policy.rs");
include!("token/sign.rs");
include!("token/dpop.rs");
include!("token/presentation_handlers.rs");
include!("token/validation.rs");
include!("token/validation_opaque.rs");
include!("token/presentation_support.rs");

pub(in crate::oauth_provider) async fn provider_api_get_client(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    client_id: &str,
) -> Result<Option<OAuthProviderClient>, OAuthProviderError> {
    resolve_client(config, store, headers, client_id).await
}

pub(in crate::oauth_provider) fn provider_api_get_issuer(
    service: &AuthService,
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
) -> String {
    provider_issuer(service, headers, config)
}

#[allow(clippy::too_many_arguments)]
pub(in crate::oauth_provider) async fn provider_api_authenticate_client(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    parameters: &BTreeMap<String, Vec<String>>,
    endpoint: &str,
    grant_type: Option<&str>,
    request: super::provider_api::OAuthProviderApiAuthenticationRequest,
) -> Result<super::provider_api::OAuthProviderAuthenticatedClient, OAuthProviderError> {
    let authenticated = authenticate_client(
        service,
        config,
        store,
        headers,
        &Parameters(parameters.clone()),
        endpoint,
        grant_type,
        request.require_credentials,
    )
    .await?;
    if !request.scopes.is_empty() {
        validate_client_scopes(config, &authenticated.client, &request.scopes)?;
    }
    Ok(super::provider_api::OAuthProviderAuthenticatedClient {
        client_id: authenticated.client.client_id.clone(),
        client: authenticated.client,
        method: authenticated.method,
        confirmation: authenticated.confirmation,
    })
}

#[allow(clippy::too_many_arguments)]
pub(in crate::oauth_provider) async fn provider_api_issue_tokens(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    endpoint: &str,
    grant_type: &str,
    input: super::provider_api::OAuthProviderApiTokenIssueInput,
) -> Result<Value, OAuthProviderError> {
    let user = match input.user_id {
        Some(user_id) => Some(
            service
                .auth_user_by_id(&user_id)
                .await
                .map_err(server)?
                .ok_or_else(|| OAuthProviderError::InvalidUser("user not found".into()))?,
        ),
        None => None,
    };
    issue_tokens(
        service,
        config,
        store,
        headers,
        IssueRequest {
            grant_type: grant_type.into(),
            endpoint: endpoint.into(),
            client: input.client,
            user,
            session_id: input.session_id,
            scopes: input.scopes,
            resources: input.resources,
            original_resources: input.original_resources,
            reference_id: input.reference_id,
            authorization_code_id: None,
            nonce: input.nonce,
            auth_time: input.auth_time,
            requested_userinfo_claims: input.requested_user_info_claims,
            verification_value: input.verification_value,
            previous_refresh: input.refresh_token,
            expected_dpop_jkt: None,
            extension_confirmation: input.confirmation,
            access_token_claims: input.access_token_claims,
            id_token_claims: input.id_token_claims,
            token_response: input.token_response,
        },
    )
    .await
}

pub(in crate::oauth_provider) async fn provider_api_hash_token(
    config: &OAuthProviderConfig,
    token_value: &str,
    token_type: OAuthStoredTokenType,
) -> Result<String, OAuthProviderError> {
    store_token(config, token_value, token_type)
        .await
        .map_err(server)
}

pub(in crate::oauth_provider) async fn provider_api_validate_resource_policy(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    client: &OAuthProviderClient,
    scopes: &[String],
    resources: Option<&[String]>,
) -> Result<(), OAuthProviderError> {
    resolve_resource_policy(service, config, store, client, scopes, resources, headers)
        .await
        .map(|_| ())
}

pub(in crate::oauth_provider) async fn provider_api_validate_access_token(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    token_value: &str,
    client_id: Option<&str>,
) -> Result<Map<String, Value>, OAuthProviderError> {
    Ok(
        validate_access_token(service, config, store, headers, token_value, client_id)
            .await?
            .payload,
    )
}

pub(in crate::oauth_provider) async fn provider_api_consume_client_assertion(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    input: super::provider_api::OAuthProviderClientAssertionInput,
) -> Result<(), OAuthProviderError> {
    let audiences = input
        .payload
        .get("aud")
        .map_or_else(Vec::new, |value| match value {
            Value::String(value) => vec![value.as_str()],
            Value::Array(values) => values.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        });
    if !audiences.contains(&input.expected_audience.as_str()) {
        return Err(OAuthProviderError::InvalidClient(
            "client assertion aud does not match the endpoint".into(),
        ));
    }
    let now = Utc::now().timestamp();
    let exp = input
        .payload
        .get("exp")
        .and_then(Value::as_f64)
        .ok_or_else(|| {
            OAuthProviderError::InvalidClient("client assertion must include exp claim".into())
        })?;
    validate_client_assertion_lifetime(config, &input.payload, now, exp)?;
    let jti = input
        .payload
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OAuthProviderError::InvalidClient("client assertion must include jti claim".into())
        })?;
    let expires_at = DateTime::from_timestamp(exp.ceil() as i64, 0).ok_or_else(|| {
        OAuthProviderError::InvalidClient("client assertion exp is invalid".into())
    })?;
    let reserved = store
        .reserve_oauth_client_assertion(
            &|| {
                service.prepare_database_id(&service.database_id_plan(
                    "oauthClientAssertion",
                    crate::DatabaseIdInput::Absent,
                    false,
                ))
            },
            OAuthProviderClientAssertion {
                id: String::new(),
                jti: client_assertion_id(&input.namespace, jti),
                expires_at,
            },
        )
        .await
        .map_err(server)?;
    if reserved {
        Ok(())
    } else {
        Err(OAuthProviderError::InvalidClient(
            "client assertion jti has already been used".into(),
        ))
    }
}
