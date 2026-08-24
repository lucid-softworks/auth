use super::OneTapConfig;
use crate::{
    AuthService, AxumPluginRoute,
    axum::{
        http::{
            PeerAddress, auth_error, client_ip, current_session, user_agent,
            with_bound_session_cookie,
        },
        with_provider_account_cookie,
    },
};
use axum::{
    Extension, Json,
    body::to_bytes,
    extract::{FromRequest, Request},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;

struct CallbackRequest {
    id_token: String,
    #[allow(dead_code)]
    callback_url: Option<String>,
}

pub(super) fn routes(
    _service: Arc<AuthService>,
    config: Arc<OneTapConfig>,
) -> Vec<AxumPluginRoute> {
    vec![AxumPluginRoute::new(
        "/one-tap/callback",
        post(callback).layer(Extension(config)),
    )]
}

async fn callback(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    OneTapBody(input): OneTapBody,
) -> Response {
    let anonymous = current_session(&service, &headers)
        .await
        .filter(|session| session.user.is_anonymous);
    match service
        .sign_in_one_tap_with_source(
            &input.id_token,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
            anonymous,
        )
        .await
    {
        Ok(result) => {
            let user = match service.better_auth_user(&result.session.user).await {
                Ok(user) => user,
                Err(error) => return auth_error(error),
            };
            let response = with_bound_session_cookie(
                &service,
                &headers,
                result.session.user.id,
                &result.token,
                Some(true),
                Json(json!({ "token": result.token, "user": user })),
            )
            .await;
            with_provider_account_cookie(
                &service,
                &headers,
                result.session.user.id,
                "google",
                response,
            )
            .await
        }
        Err(error) => callback_error(error),
    }
}

struct OneTapBody(CallbackRequest);

impl<S> FromRequest<S> for OneTapBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = to_bytes(request.into_body(), 1024 * 1024)
            .await
            .map_err(|_| {
                auth_error(crate::AuthError::InvalidRequest(
                    "request body is too large".into(),
                ))
            })?;
        if bytes.is_empty() {
            return parse_callback(json!({}))
                .map(Self)
                .map_err(validation_error);
        }
        let allowed_content_type = content_type
            .as_deref()
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().contains("application/json"));
        if !allowed_content_type {
            let message = content_type.map_or_else(
                || "Content-Type is required. Allowed types: application/json".into(),
                |content_type| {
                    format!(
                        "Content-Type \"{content_type}\" is not allowed. Allowed types: application/json"
                    )
                },
            );
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(CodedError {
                    code: "UNSUPPORTED_MEDIA_TYPE",
                    message,
                }),
            )
                .into_response());
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(CodedError {
                    code: "BAD_REQUEST",
                    message: "Invalid JSON in request body".into(),
                }),
            )
                .into_response()
        })?;
        parse_callback(value).map(Self).map_err(validation_error)
    }
}

fn validation_error(message: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(CodedError {
            code: "VALIDATION_ERROR",
            message,
        }),
    )
        .into_response()
}

fn parse_callback(value: serde_json::Value) -> Result<CallbackRequest, String> {
    let object = value
        .as_object()
        .ok_or_else(|| validation_message("object", &[], json_type(&value)))?;
    let id_token = match object.get("idToken") {
        Some(serde_json::Value::String(value)) => value.clone(),
        value => {
            return Err(validation_message(
                "string",
                &["idToken"],
                json_type_opt(value),
            ));
        }
    };
    let callback_url = match object.get("callbackURL") {
        None => None,
        Some(serde_json::Value::String(value)) => Some(value.clone()),
        value => {
            return Err(validation_message(
                "string",
                &["callbackURL"],
                json_type_opt(value),
            ));
        }
    };
    Ok(CallbackRequest {
        id_token,
        callback_url,
    })
}

fn validation_message(expected: &str, path: &[&str], received: &str) -> String {
    let path = match path {
        [] => "[]".into(),
        [field] => format!("[\n      \"{field}\"\n    ]"),
        _ => unreachable!("One Tap validation paths have at most one field"),
    };
    format!(
        "[\n  {{\n    \"expected\": \"{expected}\",\n    \"code\": \"invalid_type\",\n    \"path\": {path},\n    \"message\": \"Invalid input: expected {expected}, received {received}\"\n  }}\n]"
    )
}

fn json_type_opt(value: Option<&serde_json::Value>) -> &'static str {
    value.map_or("undefined", json_type)
}

fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[derive(Serialize)]
struct MessageError<'a> {
    message: &'a str,
}

#[derive(Serialize)]
struct CodedError {
    code: &'static str,
    message: String,
}

fn callback_error(error: crate::AuthError) -> Response {
    use crate::{AuthError, OneTapError};
    match error {
        AuthError::OneTap(error) => {
            let message = match error {
                OneTapError::MissingClientId => {
                    "Google client ID is required for One Tap. Set it on the oneTap plugin (clientId) or on socialProviders.google."
                }
                OneTapError::InvalidIdToken => "invalid id token",
                OneTapError::EmailNotAvailable => "Email not available in token",
            };
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(MessageError { message }),
            )
                .into_response()
        }
        AuthError::OAuthAccountNotLinked => (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(MessageError {
                message: "account not linked",
            }),
        )
            .into_response(),
        AuthError::OAuthSignupDisabled => (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(MessageError {
                message: "signup disabled",
            }),
        )
            .into_response(),
        error => auth_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, BuiltinProvider, BuiltinProviderKind, MemoryStore, OneTapPlugin,
        oauth::google_id_token::fixture,
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    #[tokio::test]
    async fn successful_callback_returns_user_and_binds_session_and_account_cookies() {
        let (verifier, token) = fixture::verifier_and_token(json!({
            "sub": "http-one-tap",
            "email": "HTTP.OneTap@Example.com"
        }));
        let mut auth = AuthConfig::new([116_u8; 32]).unwrap();
        auth.set_base_url("http://localhost").unwrap();
        auth.account.store_account_cookie = true;
        auth.session.cookie_cache.enabled = true;
        let one_tap = OneTapConfig {
            client_id: Some(fixture::AUDIENCE.into()),
            verifier,
            ..OneTapConfig::default()
        };
        auth.add_plugin(OneTapPlugin::new(one_tap)).unwrap();
        let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), auth));
        let response = crate::axum::router(service)
            .oneshot(
                Request::post("/api/auth/one-tap/callback")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ORIGIN, "http://localhost")
                    .body(Body::from(
                        json!({ "idToken": token, "callbackURL": "/dashboard" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key(header::LOCATION));
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(cookies.contains("better-auth.session_token="));
        assert!(cookies.contains("better-auth.session_data="));
        assert!(cookies.contains("better-auth.account_data="));
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body.as_object().unwrap().len(), 2);
        assert!(
            body["token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );
        assert_eq!(body["user"]["email"], "http.onetap@example.com");
    }

    #[tokio::test]
    async fn callback_maps_oauth_policy_errors_exactly() {
        let (verifier, token) = fixture::verifier_and_token(json!({
            "sub": "http-unverified",
            "email_verified": false
        }));
        let mut auth = AuthConfig::new([117_u8; 32]).unwrap();
        auth.set_base_url("http://localhost").unwrap();
        let mut google =
            BuiltinProvider::public_client(BuiltinProviderKind::Google, fixture::AUDIENCE);
        google.config_mut().require_email_verification = true;
        auth.add_social_provider(google).unwrap();
        auth.add_plugin(OneTapPlugin::new(OneTapConfig {
            client_id: Some(fixture::AUDIENCE.into()),
            verifier,
            ..OneTapConfig::default()
        }))
        .unwrap();
        let app = crate::axum::router(Arc::new(AuthService::new(
            Arc::new(MemoryStore::default()),
            auth,
        )));
        let response = callback_request(&app, &token).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_body(response).await,
            json!({ "code": "EMAIL_NOT_VERIFIED", "message": "Email not verified" })
        );

        let (verifier, token) = fixture::verifier_and_token(json!({
            "sub": "http-signup-disabled"
        }));
        let mut auth = AuthConfig::new([118_u8; 32]).unwrap();
        auth.set_base_url("http://localhost").unwrap();
        auth.add_plugin(OneTapPlugin::new(OneTapConfig {
            client_id: Some(fixture::AUDIENCE.into()),
            disable_signup: true,
            verifier,
        }))
        .unwrap();
        let app = crate::axum::router(Arc::new(AuthService::new(
            Arc::new(MemoryStore::default()),
            auth,
        )));
        let response = callback_request(&app, &token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_body(response).await,
            json!({ "message": "signup disabled" })
        );
    }

    async fn callback_request(app: &axum::Router, token: &str) -> Response {
        app.clone()
            .oneshot(
                Request::post("/api/auth/one-tap/callback")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ORIGIN, "http://localhost")
                    .body(Body::from(json!({ "idToken": token }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn response_body(response: Response) -> Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }
}
