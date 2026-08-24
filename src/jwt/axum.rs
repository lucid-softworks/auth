use super::{JwtAdapterContext, JwtConfig, JwtSession, keyring};
use crate::{AuthError, AuthService, AxumPluginRoute, PluginRequestContext};
use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::sync::Arc;

const MAX_SESSION_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn routes(_service: Arc<AuthService>, config: Arc<JwtConfig>) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            config.jwks.jwks_path.clone(),
            get(get_jwks).layer(Extension(config.clone())),
        ),
        AxumPluginRoute::new("/token", get(get_token).layer(Extension(config))),
    ]
}

pub(super) async fn after_response(
    service: &AuthService,
    config: &JwtConfig,
    request: &PluginRequestContext,
    response: Response,
) -> Response {
    if config.disable_setting_jwt_header
        || request.path != "/get-session"
        || !response.status().is_success()
    {
        return response;
    }
    let (parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_SESSION_RESPONSE_BYTES).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let mut response = Response::from_parts(parts, Body::from(bytes.clone()));
    let Some(session) = session_from_response(&bytes) else {
        return response;
    };
    let context = adapter_context(request);
    let token = match super::token::get_jwt_token(service, config, &context, &session).await {
        Ok(token) => token,
        Err(error) => return no_store(crate::axum::http::auth_error(error)),
    };
    let Ok(token) = HeaderValue::from_str(&token) else {
        return no_store(crate::axum::http::auth_error(AuthError::Jwt(
            super::JwtError::Signing,
        )));
    };
    response.headers_mut().insert("set-auth-jwt", token);
    expose_header(response)
}

async fn get_jwks(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<JwtConfig>>,
    headers: HeaderMap,
) -> Response {
    if config
        .jwks
        .remote_url
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let context = header_context("GET", &config.jwks.jwks_path, &headers);
    let mut keys = match keyring::all_keys(&service, &config, &context).await {
        Ok(keys) => keys,
        Err(error) => return no_store(crate::axum::http::auth_error(error)),
    };
    if keys.is_empty() {
        let primary = config.jwks.key_pair_config.unwrap_or_default();
        if let Err(error) = keyring::create(&service, &config, &context, primary).await {
            return no_store(crate::axum::http::auth_error(error));
        }
        keys = match keyring::all_keys(&service, &config, &context).await {
            Ok(keys) => keys,
            Err(error) => return no_store(crate::axum::http::auth_error(error)),
        };
    }
    if keys.is_empty() {
        return no_store(crate::axum::http::auth_error(AuthError::Jwt(
            super::JwtError::NoKeySets,
        )));
    }
    let now = chrono::Utc::now();
    let keys = keys
        .into_iter()
        .filter(|key| {
            key.expires_at.is_none_or(|expires| {
                expires
                    + config
                        .jwks
                        .grace_period
                        .unwrap_or_else(|| chrono::Duration::days(30))
                    > now
            })
        })
        .filter_map(|key| public_jwk(&config, key))
        .collect();
    Json(JwksResponse { keys }).into_response()
}

async fn get_token(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<JwtConfig>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = crate::axum::http::current_session_cache_first(&service, &headers).await
    else {
        return no_store(crate::axum::http::auth_error(AuthError::Unauthorized));
    };
    let response = match service
        .better_auth_session_response(&session, session.session.token.clone())
        .await
    {
        Ok(response) => response,
        Err(error) => return no_store(crate::axum::http::auth_error(error)),
    };
    let session = match serde_json::to_value(response) {
        Ok(value) => JwtSession {
            user: value["user"].clone(),
            session: value["session"].clone(),
        },
        Err(_) => {
            return no_store(crate::axum::http::auth_error(AuthError::Jwt(
                super::JwtError::Signing,
            )));
        }
    };
    let context = header_context("GET", "/token", &headers);
    match super::token::get_jwt_token(&service, &config, &context, &session).await {
        Ok(token) => no_store(Json(TokenResponse { token }).into_response()),
        Err(error) => no_store(crate::axum::http::auth_error(error)),
    }
}

fn session_from_response(bytes: &[u8]) -> Option<JwtSession> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object()?;
    Some(JwtSession {
        user: object.get("user")?.clone(),
        session: object.get("session")?.clone(),
    })
}

fn public_jwk(config: &JwtConfig, key: super::StoredJwk) -> Option<Value> {
    let primary = config.jwks.key_pair_config.unwrap_or_default();
    let mut value = Map::new();
    value.insert(
        "alg".into(),
        Value::String(key.alg.clone().unwrap_or_else(|| primary.name().to_owned())),
    );
    if let Some(crv) = key
        .crv
        .clone()
        .or_else(|| primary.curve().map(str::to_owned))
    {
        value.insert("crv".into(), Value::String(crv));
    }
    value.extend(serde_json::from_str::<Map<String, Value>>(&key.public_key).ok()?);
    value.insert("kid".into(), Value::String(key.id));
    Some(Value::Object(value))
}

fn expose_header(mut response: Response) -> Response {
    let existing = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut names = existing
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !names.iter().any(|name| name == "set-auth-jwt") {
        names.push("set-auth-jwt".into());
    }
    if let Ok(value) = HeaderValue::from_str(&names.join(", ")) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, value);
    }
    response
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn adapter_context(request: &PluginRequestContext) -> JwtAdapterContext {
    JwtAdapterContext {
        method: Some(request.method.clone()),
        path: Some(request.path.clone()),
        query: request.query.clone(),
        headers: request.headers.clone(),
    }
}

fn header_context(method: &str, path: &str, headers: &HeaderMap) -> JwtAdapterContext {
    JwtAdapterContext {
        method: Some(method.into()),
        path: Some(path.into()),
        query: None,
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect(),
    }
}

#[derive(Serialize)]
struct JwksResponse {
    keys: Vec<Value>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}
