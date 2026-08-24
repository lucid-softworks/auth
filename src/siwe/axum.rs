use super::{SiweConfig, SiweError, request_origin::request_base_origin};
use crate::{
    AuthError, AuthService, AxumPluginRoute,
    axum::http::{PeerAddress, auth_error, client_ip, user_agent, with_bound_session_cookie_cache},
};
use axum::{
    Extension, Json,
    body::{Bytes, to_bytes},
    extract::{FromRequest, Request},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) fn routes(_service: Arc<AuthService>, config: Arc<SiweConfig>) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/siwe/nonce", post(nonce).layer(Extension(config.clone()))),
        AxumPluginRoute::new(
            "/siwe/get-nonce",
            post(nonce).layer(Extension(config.clone())),
        ),
        AxumPluginRoute::new("/siwe/verify", post(verify).layer(Extension(config))),
    ]
}

async fn nonce(Extension(service): Extension<Arc<AuthService>>, _: EmptyBody) -> Response {
    match service.create_siwe_nonce().await {
        Ok(nonce) => Json(json!({ "nonce": nonce })).into_response(),
        Err(error) => siwe_error(error),
    }
}

async fn verify(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    VerifyBody(input): VerifyBody,
) -> Response {
    let base_origin = request_base_origin(&service, &headers, &input.uri);
    match service
        .verify_siwe_message(
            input.message,
            input.signature,
            input.email,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
            base_origin,
        )
        .await
    {
        Ok(result) => {
            let token = result.token.clone();
            let cache = match service.encode_session_cookie_cache(&token, None).await {
                Ok(cache) => cache,
                Err(error) => {
                    return siwe_error(AuthError::Siwe(SiweError::Unexpected(error.to_string())));
                }
            };
            with_bound_session_cookie_cache(
                &service,
                &headers,
                result.user_id,
                &token,
                cache.as_deref(),
                Json(json!({
                    "token": token,
                    "success": true,
                    "user": {
                        "id": result.user_id,
                        "walletAddress": result.wallet_address,
                        "chainId": result.chain_id
                    }
                })),
            )
        }
        Err(error) => siwe_error(error),
    }
}

struct EmptyBody;

impl<S: Send + Sync> FromRequest<S> for EmptyBody {
    type Rejection = RequestRejection;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let (content_type, bytes) = request_parts(request).await?;
        if bytes.is_empty() {
            return Ok(Self);
        }
        require_json(content_type.as_deref())?;
        let value = parse_json(&bytes)?;
        let object = value.as_object().ok_or_else(|| {
            validation_error(format!(
                "[body] Invalid input: expected object, received {}",
                json_type(&value)
            ))
        })?;
        if !object.is_empty() {
            return Err(validation_error(unknown_keys(object.keys())));
        }
        Ok(Self)
    }
}

struct VerifyInput {
    message: String,
    signature: String,
    email: Option<String>,
    uri: axum::http::Uri,
}

struct VerifyBody(VerifyInput);

impl<S: Send + Sync> FromRequest<S> for VerifyBody {
    type Rejection = RequestRejection;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let anonymous = request
            .extensions()
            .get::<Arc<SiweConfig>>()
            .is_none_or(|config| config.anonymous);
        let uri = request.uri().clone();
        let (content_type, bytes) = request_parts(request).await?;
        if bytes.is_empty() {
            return Err(validation_error(
                "[body] Invalid input: expected object, received undefined".into(),
            ));
        }
        require_json(content_type.as_deref())?;
        let value = parse_json(&bytes)?;
        let object = value.as_object().ok_or_else(|| {
            validation_error(format!(
                "[body] Invalid input: expected object, received {}",
                json_type(&value)
            ))
        })?;
        let mut issues = Vec::new();
        validate_required_string(object, "message", &mut issues);
        validate_required_string(object, "signature", &mut issues);
        validate_email(object.get("email"), &mut issues);
        let unknown = object
            .keys()
            .filter(|key| !matches!(key.as_str(), "message" | "signature" | "email"));
        let unknown: Vec<_> = unknown.collect();
        let refinement_allowed = unknown.is_empty()
            && matches!(object.get("message"), Some(Value::String(_)))
            && matches!(object.get("signature"), Some(Value::String(_)))
            && matches!(object.get("email"), None | Some(Value::String(_)));
        if !unknown.is_empty() {
            issues.push(unknown_keys(unknown.into_iter()));
        }
        if refinement_allowed
            && !anonymous
            && object
                .get("email")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            issues.push(
                "[body.email] Email is required when the anonymous plugin option is disabled."
                    .into(),
            );
        }
        if !issues.is_empty() {
            return Err(validation_error(issues.join("; ")));
        }
        Ok(Self(VerifyInput {
            message: object["message"].as_str().unwrap().into(),
            signature: object["signature"].as_str().unwrap().into(),
            email: object.get("email").and_then(Value::as_str).map(Into::into),
            uri,
        }))
    }
}

fn validate_required_string(
    object: &serde_json::Map<String, Value>,
    name: &str,
    issues: &mut Vec<String>,
) {
    match object.get(name) {
        None => issues.push(format!(
            "[body.{name}] Invalid input: expected string, received undefined"
        )),
        Some(Value::String(value)) if value.is_empty() => issues.push(format!(
            "[body.{name}] Too small: expected string to have >=1 characters"
        )),
        Some(Value::String(_)) => {}
        Some(value) => issues.push(format!(
            "[body.{name}] Invalid input: expected string, received {}",
            json_type(value)
        )),
    }
}

fn validate_email(value: Option<&Value>, issues: &mut Vec<String>) {
    match value {
        None => {}
        Some(Value::String(email)) if crate::service::valid_email(email) => {}
        Some(Value::String(_)) => issues.push("[body.email] Invalid email address".into()),
        Some(value) => issues.push(format!(
            "[body.email] Invalid input: expected string, received {}",
            json_type(value)
        )),
    }
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn unknown_keys<'a>(keys: impl Iterator<Item = &'a String>) -> String {
    let keys: Vec<_> = keys.map(|key| format!("\"{key}\"")).collect();
    let noun = if keys.len() == 1 { "key" } else { "keys" };
    format!("[body] Unrecognized {noun}: {}", keys.join(", "))
}

struct RequestRejection(Box<Response>);

impl IntoResponse for RequestRejection {
    fn into_response(self) -> Response {
        *self.0
    }
}

async fn request_parts(request: Request) -> Result<(Option<String>, Bytes), RequestRejection> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|_| {
            rejection(auth_error(AuthError::InvalidRequest(
                "request body is too large".into(),
            )))
        })?;
    Ok((content_type, bytes))
}

fn require_json(content_type: Option<&str>) -> Result<(), RequestRejection> {
    let allowed = content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            let value = value.trim().to_ascii_lowercase();
            value == "application/json"
                || value
                    .strip_prefix("application/")
                    .is_some_and(|subtype| subtype.ends_with("+json"))
        });
    if allowed {
        return Ok(());
    }
    let message = content_type.map_or_else(
        || "Content-Type is required. Allowed types: application/json".into(),
        |content_type| {
            format!(
                "Content-Type \"{content_type}\" is not allowed. Allowed types: application/json"
            )
        },
    );
    Err(rejection(coded_error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "UNSUPPORTED_MEDIA_TYPE",
        &message,
    )))
}

fn parse_json(bytes: &[u8]) -> Result<Value, RequestRejection> {
    serde_json::from_slice(bytes).map_err(|_| {
        rejection(coded_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid JSON in request body",
        ))
    })
}

fn validation_error(message: String) -> RequestRejection {
    rejection(coded_error(
        StatusCode::BAD_REQUEST,
        "VALIDATION_ERROR",
        &message,
    ))
}

fn rejection(response: Response) -> RequestRejection {
    RequestRejection(Box::new(response))
}

fn siwe_error(error: AuthError) -> Response {
    let AuthError::Siwe(error) = error else {
        return auth_error(error);
    };
    match error {
        SiweError::NonceCallback(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        SiweError::InvalidGeneratedNonce => siwe_api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.",
            Some("SIWE_INVALID_NONCE"),
            None,
        ),
        SiweError::MessageMismatch => siwe_api_error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID",
            Some("UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"),
            None,
        ),
        SiweError::InvalidOrExpiredNonce => siwe_api_error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized: Invalid or expired nonce",
            Some("UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"),
            None,
        ),
        SiweError::MessageExpired => siwe_api_error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized: SIWE message has expired",
            Some("UNAUTHORIZED_SIWE_MESSAGE_EXPIRED"),
            None,
        ),
        SiweError::MessageNotYetValid => siwe_api_error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized: SIWE message is not yet valid",
            Some("UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID"),
            None,
        ),
        SiweError::InvalidSignature => siwe_api_error(
            StatusCode::UNAUTHORIZED,
            "Unauthorized: Invalid SIWE signature",
            None,
            None,
        ),
        SiweError::EmailRequired => siwe_api_error(
            StatusCode::BAD_REQUEST,
            "Email is required when anonymous is disabled.",
            None,
            None,
        ),
        SiweError::Unexpected(error) => siwe_api_error(
            StatusCode::UNAUTHORIZED,
            "Something went wrong. Please try again later.",
            None,
            Some(&error),
        ),
    }
}

fn siwe_api_error(
    status: StatusCode,
    message: &str,
    code: Option<&str>,
    error: Option<&str>,
) -> Response {
    let mut body = serde_json::Map::from_iter([
        ("message".into(), Value::String(message.into())),
        ("status".into(), json!(status.as_u16())),
    ]);
    if let Some(code) = code {
        body.insert("code".into(), Value::String(code.into()));
    }
    if let Some(error) = error {
        body.insert("error".into(), Value::String(error.into()));
    }
    (status, Json(Value::Object(body))).into_response()
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
}

fn coded_error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(ErrorBody { code, message })).into_response()
}
