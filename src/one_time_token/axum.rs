use super::{OneTimeTokenConfig, OneTimeTokenError, OneTimeTokenRequestContext};
use crate::{AuthError, AuthService, AxumPluginRoute, PluginRequestContext};
use axum::{
    Extension, Json,
    extract::rejection::JsonRejection,
    http::{HeaderMap, HeaderValue, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    config: Arc<OneTimeTokenConfig>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/one-time-token/generate",
            get(generate).layer(Extension(config.clone())),
        ),
        AxumPluginRoute::new(
            "/one-time-token/verify",
            post(verify).layer(Extension(config)),
        ),
    ]
}

#[derive(Serialize)]
struct GenerateResponse {
    token: String,
}

async fn generate(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OneTimeTokenConfig>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(session) = crate::axum::http::current_session_cache_first(&service, &headers).await
    else {
        return crate::axum::http::auth_error(AuthError::Unauthorized);
    };
    if config.disable_client_request {
        return crate::axum::http::auth_error(OneTimeTokenError::ClientRequestsDisabled.into());
    }
    let context = request_context("GET", "/one-time-token/generate", uri.query(), &headers);
    match service
        .generate_one_time_token_with(&config, &session, &context)
        .await
    {
        Ok(token) => Json(GenerateResponse { token }).into_response(),
        Err(error) => crate::axum::http::auth_error(error),
    }
}

async fn verify(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OneTimeTokenConfig>>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let input = match body {
        Ok(Json(input)) => input,
        Err(JsonRejection::MissingJsonContentType(_)) => {
            let content_type = headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("text/plain;charset=UTF-8");
            return coded_error(
                axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                format!(
                    "Content-Type \"{content_type}\" is not allowed. Allowed types: application/json"
                ),
            );
        }
        Err(_) => {
            return coded_error(
                axum::http::StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid JSON in request body".into(),
            );
        }
    };
    let token = match verify_token(input) {
        Ok(token) => token,
        Err(message) => return validation_error(message),
    };
    let session = match service.consume_one_time_token_with(&config, &token).await {
        Ok(session) => session,
        Err(error) => return crate::axum::http::auth_error(error),
    };
    let session_response = match service
        .better_auth_session_response(&session, session.session.token.clone())
        .await
    {
        Ok(response) => response,
        Err(error) => return crate::axum::http::auth_error(error),
    };
    if config.disable_set_session_cookie {
        return if session.session.expires_at < chrono::Utc::now() {
            crate::axum::http::auth_error(OneTimeTokenError::SessionExpired.into())
        } else {
            Json(session_response).into_response()
        };
    }
    let remember_me = crate::axum::http::dont_remember(&service, &headers).then_some(false);
    let response = crate::axum::http::with_bound_session_cookie(
        &service,
        &headers,
        &session.user.id,
        &session.session.token,
        remember_me,
        Json(session_response),
    )
    .await;
    if session.session.expires_at < chrono::Utc::now() {
        replace_with_error(response, OneTimeTokenError::SessionExpired.into())
    } else {
        response
    }
}

pub(super) async fn after_response(
    service: &AuthService,
    config: &OneTimeTokenConfig,
    request: &PluginRequestContext,
    mut response: Response,
) -> Response {
    if !config.set_ott_header_on_new_session {
        return response;
    }
    let Some(session) = response
        .extensions()
        .get::<crate::axum::http::BoundSession>()
        .map(|bound| bound.0.clone())
    else {
        return response;
    };
    let context = OneTimeTokenRequestContext {
        method: Some(request.method.clone()),
        path: Some(request.path.clone()),
        query: request.query.clone(),
        headers: request.headers.clone(),
    };
    let token = match service
        .generate_one_time_token_with(config, &session, &context)
        .await
    {
        Ok(token) => token,
        Err(error) => return replace_with_error(response, error),
    };
    let Ok(token) = HeaderValue::from_str(&token) else {
        return replace_with_error(
            response,
            AuthError::InvalidConfiguration(
                "one-time-token generators must return an HTTP header value".into(),
            ),
        );
    };
    response.headers_mut().insert("set-ott", token);
    expose_header(response)
}

fn request_context(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> OneTimeTokenRequestContext {
    OneTimeTokenRequestContext {
        method: Some(method.into()),
        path: Some(path.into()),
        query: query.map(str::to_owned),
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
        .fold(Vec::<String>::new(), |mut names, name| {
            if !names.iter().any(|existing| existing == &name) {
                names.push(name);
            }
            names
        });
    if !names.iter().any(|name| name == "set-ott") {
        names.push("set-ott".into());
    }
    if let Ok(value) = HeaderValue::from_str(&names.join(", ")) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, value);
    }
    response
}

fn verify_token(value: serde_json::Value) -> Result<String, String> {
    let Some(object) = value.as_object() else {
        let received = match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => unreachable!(),
        };
        return Err(format!(
            "[body] Invalid input: expected object, received {received}"
        ));
    };
    match object.get("token") {
        Some(serde_json::Value::String(token)) => Ok(token.clone()),
        Some(serde_json::Value::Number(_)) => {
            Err("[body.token] Invalid input: expected string, received number".into())
        }
        Some(serde_json::Value::Null) => {
            Err("[body.token] Invalid input: expected string, received null".into())
        }
        Some(serde_json::Value::Bool(_)) => {
            Err("[body.token] Invalid input: expected string, received boolean".into())
        }
        Some(serde_json::Value::Array(_)) => {
            Err("[body.token] Invalid input: expected string, received array".into())
        }
        Some(serde_json::Value::Object(_)) => {
            Err("[body.token] Invalid input: expected string, received object".into())
        }
        None => Err("[body.token] Invalid input: expected string, received undefined".into()),
    }
}

fn validation_error(message: String) -> Response {
    coded_error(
        axum::http::StatusCode::BAD_REQUEST,
        "VALIDATION_ERROR",
        message,
    )
}

fn coded_error(status: axum::http::StatusCode, code: &'static str, message: String) -> Response {
    #[derive(Serialize)]
    struct CodedError {
        code: &'static str,
        message: String,
    }
    (status, Json(CodedError { code, message })).into_response()
}

fn replace_with_error(mut response: Response, error: AuthError) -> Response {
    let failure = crate::axum::http::auth_error(error);
    *response.status_mut() = failure.status();
    response.headers_mut().extend(failure.headers().clone());
    *response.body_mut() = failure.into_body();
    response
}
