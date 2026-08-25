use crate::oauth_provider::{OAuthProviderClient, OAuthProviderConfig, OAuthProviderError};
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};

use super::super::response::no_store;

pub(super) fn client_json(
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    exposed_secret: Option<&str>,
    resources: Option<&[String]>,
) -> Value {
    let mut output = match &client.metadata {
        Some(Value::Object(metadata)) => metadata.clone(),
        _ => Map::new(),
    };
    insert_client_identity(&mut output, client, exposed_secret);
    insert_client_presentation(&mut output, client);
    insert_client_protocol(&mut output, client);
    if let Some(resources) = resources {
        output.insert("resources".into(), json!(resources));
    }
    extend_client_metadata(config, client, &mut output);
    Value::Object(output)
}

fn extend_client_metadata(
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    output: &mut Map<String, Value>,
) {
    let base = output.clone();
    for extension in &config.extensions {
        for (name, value) in extension.client_metadata(client, &base) {
            output.entry(name).or_insert(value);
        }
    }
}

fn insert_client_identity(
    output: &mut Map<String, Value>,
    client: &OAuthProviderClient,
    exposed_secret: Option<&str>,
) {
    output.insert("client_id".into(), json!(client.client_id));
    if let Some(secret) = exposed_secret {
        output.insert("client_secret".into(), json!(secret));
    }
    if client.client_secret.is_some() {
        output.insert(
            "client_secret_expires_at".into(),
            json!(
                client
                    .expires_at
                    .map(|value| value.timestamp())
                    .unwrap_or(0)
            ),
        );
    }
    if let Some(scopes) = &client.scopes {
        output.insert("scope".into(), json!(scopes.join(" ")));
    }
    if let Some(user_id) = client.user_id {
        output.insert("user_id".into(), json!(user_id));
    }
    if let Some(created_at) = client.created_at {
        output.insert("client_id_issued_at".into(), json!(created_at.timestamp()));
    }
}

fn insert_client_presentation(output: &mut Map<String, Value>, client: &OAuthProviderClient) {
    optional(output, "client_name", client.name.as_ref());
    optional(output, "client_uri", client.uri.as_ref());
    optional(output, "logo_uri", client.icon.as_ref());
    optional(output, "contacts", client.contacts.as_ref());
    optional(output, "tos_uri", client.tos.as_ref());
    optional(output, "policy_uri", client.policy.as_ref());
    optional(output, "software_id", client.software_id.as_ref());
    optional(output, "software_version", client.software_version.as_ref());
    optional(
        output,
        "software_statement",
        client.software_statement.as_ref(),
    );
    output.insert("redirect_uris".into(), json!(client.redirect_uris));
    optional(
        output,
        "post_logout_redirect_uris",
        client.post_logout_redirect_uris.as_ref(),
    );
    optional(
        output,
        "backchannel_logout_uri",
        client.backchannel_logout_uri.as_ref(),
    );
    optional(
        output,
        "backchannel_logout_session_required",
        client.backchannel_logout_session_required.as_ref(),
    );
}

fn insert_client_protocol(output: &mut Map<String, Value>, client: &OAuthProviderClient) {
    if let Some(jwks) = client
        .jwks
        .as_deref()
        .and_then(|jwks| serde_json::from_str::<Value>(jwks).ok())
    {
        output.insert("jwks".into(), jwks);
    }
    optional(output, "jwks_uri", client.jwks_uri.as_ref());
    optional(
        output,
        "token_endpoint_auth_method",
        client.token_endpoint_auth_method.as_ref(),
    );
    optional(output, "grant_types", client.grant_types.as_ref());
    optional(output, "response_types", client.response_types.as_ref());
    optional(output, "application_type", client.application_type.as_ref());
    optional(output, "disabled", Some(&client.disabled));
    optional(output, "skip_consent", client.skip_consent.as_ref());
    optional(
        output,
        "enable_end_session",
        client.enable_end_session.as_ref(),
    );
    optional(output, "require_pkce", client.require_pkce.as_ref());
    optional(
        output,
        "dpop_bound_access_tokens",
        Some(&client.dpop_bound_access_tokens),
    );
    optional(output, "subject_type", client.subject_type.as_ref());
    optional(output, "reference_id", client.reference_id.as_ref());
}

pub(super) fn public_client_json(
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
) -> Value {
    let mut output = Map::new();
    output.insert("client_id".into(), json!(client.client_id));
    optional(&mut output, "client_name", client.name.as_ref());
    optional(&mut output, "client_uri", client.uri.as_ref());
    optional(&mut output, "logo_uri", client.icon.as_ref());
    optional(&mut output, "contacts", client.contacts.as_ref());
    optional(&mut output, "tos_uri", client.tos.as_ref());
    optional(&mut output, "policy_uri", client.policy.as_ref());
    output.insert("redirect_uris".into(), json!([]));
    extend_client_metadata(config, client, &mut output);
    Value::Object(output)
}

fn optional<T: serde::Serialize>(output: &mut Map<String, Value>, key: &str, value: Option<&T>) {
    if let Some(value) = value.and_then(|value| serde_json::to_value(value).ok()) {
        output.insert(key.into(), value);
    }
}

pub(super) fn registration_protocol_error(error: OAuthProviderError) -> Response {
    metadata_protocol_error(error, true)
}

pub(super) fn metadata_protocol_error(
    error: OAuthProviderError,
    no_store_response: bool,
) -> Response {
    let (code, description) = match error {
        OAuthProviderError::InvalidScope(description) => ("invalid_scope", description),
        OAuthProviderError::InvalidRedirectUri(description) => {
            ("invalid_redirect_uri", description)
        }
        OAuthProviderError::InvalidRequest(description) => {
            let code = if description.starts_with("requested resource") {
                "invalid_target"
            } else {
                "invalid_client_metadata"
            };
            (code, description)
        }
        OAuthProviderError::InvalidClient(description)
        | OAuthProviderError::UnauthorizedInvalidClient(description)
        | OAuthProviderError::BasicInvalidClient(description) => {
            ("invalid_client_metadata", description)
        }
        OAuthProviderError::ChallengedInvalidClient { description, .. } => {
            ("invalid_client_metadata", description)
        }
        OAuthProviderError::ServerError(description) => ("server_error", description),
        other => (other.code(), other.to_string()),
    };
    let status = if code == "server_error" {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    let response = (
        status,
        Json(json!({ "error": code, "error_description": description })),
    )
        .into_response();
    if no_store_response {
        no_store(response)
    } else {
        response
    }
}

pub(super) fn registration_bearer_error(
    status: StatusCode,
    code: &str,
    description: &str,
) -> Response {
    let mut response = registration_error(status, code, description);
    let challenge = format!("Bearer error=\"{code}\"");
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

pub(super) fn registration_error(status: StatusCode, code: &str, description: &str) -> Response {
    no_store(
        (
            status,
            Json(json!({
                "error": code,
                "error_description": description,
            })),
        )
            .into_response(),
    )
}

pub(super) fn endpoint_error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        Json(json!({
            "error": code,
            "error_description": description,
        })),
    )
        .into_response()
}
