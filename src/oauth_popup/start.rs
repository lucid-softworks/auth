use super::{
    POPUP_MARKER_COOKIE,
    completion::{self, CompletionMessage},
    cookies,
    service::{PopupAuthorizationInput, additional_data},
};
use crate::{AuthService, origin::safe_relative_callback};
use axum::{
    Extension, Json,
    body::Body,
    extract::RawQuery,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

struct StartQuery {
    provider: String,
    popup_origin: String,
    popup_nonce: Option<String>,
    callback_url: Option<String>,
    error_callback_url: Option<String>,
    new_user_callback_url: Option<String>,
    scopes: Option<String>,
    request_sign_up: Option<String>,
    additional_data: Option<String>,
}

#[derive(Serialize)]
struct CodedError<'a> {
    code: &'a str,
    message: &'a str,
}

pub(super) async fn start(
    Extension(service): Extension<Arc<AuthService>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let query = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(message) => return validation_error(&message),
    };
    if !service.trusts_origin(&query.popup_origin) {
        return (
            StatusCode::FORBIDDEN,
            Json(CodedError {
                code: "INVALID_ORIGIN",
                message: "Invalid origin",
            }),
        )
            .into_response();
    }
    let origin = query.popup_origin.clone();
    let nonce = Value::String(query.popup_nonce.clone().unwrap_or_default());
    if let Some(response) = redirect_validation_error(&service, &query, &origin, &nonce) {
        return response;
    }
    if service.social_provider(&query.provider).is_none() {
        return popup_error(
            &origin,
            nonce,
            "provider_not_found",
            format!("Unknown provider: {}", query.provider),
        );
    }
    begin_authorization(&service, query, origin, nonce).await
}

async fn begin_authorization(
    service: &AuthService,
    query: StartQuery,
    origin: String,
    nonce: Value,
) -> Response {
    let callback_url = query
        .callback_url
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| service.oauth_base_url().unwrap_or_default());
    let authorization = service
        .start_popup_authorization(PopupAuthorizationInput {
            provider: query.provider,
            callback_url,
            error_callback_url: query.error_callback_url,
            new_user_callback_url: query.new_user_callback_url,
            scopes: query
                .scopes
                .filter(|value| !value.is_empty())
                .map(|value| value.split(',').map(str::to_owned).collect()),
            request_sign_up: query.request_sign_up.as_deref() == Some("true"),
            additional_data: additional_data(query.additional_data.as_deref()),
        })
        .await;
    let authorization = match authorization {
        Ok(authorization) => authorization,
        Err(_) => return start_failure(&origin, nonce),
    };
    let state_cookie = cookies::core(
        &service.plugin_cookie(authorization.state_cookie_name),
        &authorization.state_cookie_value,
        authorization.state_cookie_max_age,
    );
    let marker_value = serde_json::json!({
        "popupOrigin": origin,
        "popupNonce": query.popup_nonce.unwrap_or_default(),
    })
    .to_string();
    let marker_cookie = cookies::marker(
        &service.plugin_cookie(POPUP_MARKER_COOKIE),
        &service.signed_cookie_value(&marker_value),
        Some(600.0),
        false,
    );
    let marker_cookie = match marker_cookie {
        Ok(cookie) => cookie,
        Err(_) => return cookies::append(start_failure(&origin, nonce), state_cookie),
    };
    let response = redirect_or_failure(authorization.authorization_url, &origin, nonce);
    cookies::append(cookies::append(response, state_cookie), marker_cookie)
}

fn redirect_or_failure(
    authorization_url: Result<String, crate::AuthError>,
    origin: &str,
    nonce: Value,
) -> Response {
    let Ok(url) = authorization_url else {
        return start_failure(origin, nonce);
    };
    let Ok(location) = HeaderValue::from_str(&url) else {
        return start_failure(origin, nonce);
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    response.headers_mut().insert(header::LOCATION, location);
    response
}

fn redirect_validation_error(
    service: &AuthService,
    query: &StartQuery,
    origin: &str,
    nonce: &Value,
) -> Option<Response> {
    for (value, code) in [
        (query.callback_url.as_deref(), "invalid_callback_url"),
        (
            query.error_callback_url.as_deref(),
            "invalid_error_callback_url",
        ),
        (
            query.new_user_callback_url.as_deref(),
            "invalid_new_user_callback_url",
        ),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty())
            && !(safe_relative_callback(value) || service.trusts_origin(value))
        {
            return Some(popup_error(
                origin,
                nonce.clone(),
                code,
                format!("Untrusted URL: {value}"),
            ));
        }
    }
    None
}

fn parse_query(raw: Option<&str>) -> Result<StartQuery, String> {
    let values = url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    let required = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| format!("Invalid input: expected string, received undefined at {name}"))
    };
    Ok(StartQuery {
        provider: required("provider")?,
        popup_origin: required("popupOrigin")?,
        popup_nonce: values.get("popupNonce").cloned(),
        callback_url: values.get("callbackURL").cloned(),
        error_callback_url: values.get("errorCallbackURL").cloned(),
        new_user_callback_url: values.get("newUserCallbackURL").cloned(),
        scopes: values.get("scopes").cloned(),
        request_sign_up: values.get("requestSignUp").cloned(),
        additional_data: values.get("additionalData").cloned(),
    })
}

fn validation_error(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(CodedError {
            code: "VALIDATION_ERROR",
            message,
        }),
    )
        .into_response()
}

fn start_failure(origin: &str, nonce: Value) -> Response {
    popup_error(
        origin,
        nonce,
        "popup_sign_in_failed",
        "Failed to start the OAuth flow.".into(),
    )
}

fn popup_error(origin: &str, nonce: Value, code: &str, description: String) -> Response {
    completion::render(
        Some(Value::String(origin.into())),
        CompletionMessage::Error {
            nonce,
            code: code.into(),
            description: Some(description),
        },
    )
}
