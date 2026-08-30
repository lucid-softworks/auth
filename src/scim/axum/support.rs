use super::super::{SCIM_MEDIA_TYPE, ScimError, ScimErrorType, ScimPlugin, plugin::ScimPrincipal};
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeMap;

#[allow(clippy::result_large_err)]
pub(super) async fn authenticate(
    plugin: &ScimPlugin,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Result<ScimPrincipal, Response> {
    let map = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    plugin
        .authenticate(
            headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()),
            method,
            path,
            map,
        )
        .await
        .map_err(error_response)
}

#[allow(clippy::result_large_err)]
pub(super) async fn parse_body<T: DeserializeOwned>(request: Request) -> Result<T, Response> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    if !matches!(content_type.as_deref(), Some("application/json" | "application/scim+json")) {
        return Err(error_response(ScimError::new(
            415,
            "SCIM requests must use application/scim+json or application/json",
        )));
    }
    let bytes = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|_| {
            error_response(ScimError::typed(
                400,
                "SCIM request body must contain valid JSON",
                ScimErrorType::InvalidSyntax,
            ))
        })?;
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        error_response(ScimError::typed(
            400,
            "SCIM request body must contain valid JSON",
            ScimErrorType::InvalidSyntax,
        ))
    })?;
    normalize_entra_booleans(&mut value);
    serde_json::from_value(value).map_err(|error| {
        error_response(ScimError::typed(
            400,
            error.to_string(),
            ScimErrorType::InvalidValue,
        ))
    })
}

fn normalize_entra_booleans(value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    if let Some(active) = object.get_mut("active") {
        normalize_boolean(active);
    }
    for attribute in ["emails", "phoneNumbers", "addresses", "roles", "entitlements"] {
        if let Some(entries) = object.get_mut(attribute).and_then(Value::as_array_mut) {
            for entry in entries {
                if let Some(primary) = entry.get_mut("primary") {
                    normalize_boolean(primary);
                }
            }
        }
    }
    if let Some(operations) = object.get_mut("Operations").and_then(Value::as_array_mut) {
        for operation in operations {
            normalize_patch_operation(operation);
        }
    }
}

fn normalize_patch_operation(operation: &mut Value) {
    let Some(operation) = operation.as_object_mut() else {
        return;
    };
    let path = operation
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_owned);
    let Some(value) = operation.get_mut("value") else {
        return;
    };
    let Some(path) = path else {
        if value.is_object() {
            normalize_entra_booleans(value);
        }
        return;
    };
    let path = strip_user_core_prefix(&path).to_ascii_lowercase();
    if path == "active" {
        normalize_boolean(value);
        return;
    }
    let attribute = path
        .split(['[', '.'])
        .next()
        .unwrap_or_default()
        .trim();
    if !matches!(
        attribute,
        "emails" | "phonenumbers" | "addresses" | "roles" | "entitlements"
    ) {
        return;
    }
    if path.trim_end().ends_with(".primary") {
        normalize_boolean(value);
    } else {
        normalize_primary_values(value);
    }
}

fn strip_user_core_prefix(path: &str) -> &str {
    const PREFIX: &str = "urn:ietf:params:scim:schemas:core:2.0:User:";
    if path.len() >= PREFIX.len() && path[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        &path[PREFIX.len()..]
    } else {
        path
    }
}

fn normalize_primary_values(value: &mut Value) {
    if let Some(values) = value.as_array_mut() {
        for value in values {
            normalize_primary_values(value);
        }
        return;
    }
    if let Some(primary) = value.get_mut("primary") {
        normalize_boolean(primary);
    }
}

fn normalize_boolean(value: &mut Value) {
    let replacement = value.as_str().and_then(|value| {
        if value.eq_ignore_ascii_case("true") {
            Some(true)
        } else if value.eq_ignore_ascii_case("false") {
            Some(false)
        } else {
            None
        }
    });
    if let Some(replacement) = replacement {
        *value = Value::Bool(replacement);
    }
}

pub(super) fn json(status: StatusCode, value: impl serde::Serialize) -> Response {
    let mut response = (status, axum::Json(value)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(SCIM_MEDIA_TYPE),
    );
    response
}

pub(super) fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

pub(super) fn error_response(error: ScimError) -> Response {
    let status = StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let authenticate = error.authenticate;
    let mut response = json(status, error.body());
    if authenticate {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"SCIM\""),
        );
    }
    response
}

pub(super) fn set_location(response: &mut Response, location: &str, content_location: bool) {
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value.clone());
        if content_location {
            response.headers_mut().insert(header::CONTENT_LOCATION, value);
        }
    }
}
