use crate::{AuthError, OAuthProviderAccessToken, OAuthProviderClient, OAuthProviderRefreshToken};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

pub(super) fn decode<T: DeserializeOwned>(
    model: &str,
    record: Map<String, Value>,
) -> Result<T, AuthError> {
    serde_json::from_value(Value::Object(record))
        .map_err(|error| AuthError::Storage(format!("invalid SQLite {model} row: {error}")))
}

pub(super) fn decode_client(
    mut record: Map<String, Value>,
) -> Result<OAuthProviderClient, AuthError> {
    let secret = optional_string(record.get("clientSecret"), "clientSecret")?;
    record
        .entry("clientCredentialsScopes")
        .or_insert_with(|| Value::Array(Vec::new()));
    record
        .entry("redirectUris")
        .or_insert_with(|| Value::Array(Vec::new()));
    record
        .entry("dpopBoundAccessTokens")
        .or_insert(Value::Bool(false));
    record.entry("expiresAt").or_insert(Value::Null);
    let mut client: OAuthProviderClient = decode("oauthClient", record)?;
    client.client_secret = secret;
    Ok(client)
}

pub(super) fn decode_refresh(
    record: Map<String, Value>,
) -> Result<OAuthProviderRefreshToken, AuthError> {
    let token = required_string(record.get("token"), "token")?;
    let replay = optional_string(
        record.get("rotationReplayResponse"),
        "rotationReplayResponse",
    )?;
    let mut value: OAuthProviderRefreshToken = decode("oauthRefreshToken", record)?;
    value.token = token;
    value.rotation_replay_response = replay;
    Ok(value)
}

pub(super) fn decode_access(
    record: Map<String, Value>,
) -> Result<OAuthProviderAccessToken, AuthError> {
    let token = required_string(record.get("token"), "token")?;
    let mut value: OAuthProviderAccessToken = decode("oauthAccessToken", record)?;
    value.token = token;
    Ok(value)
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, AuthError> {
    match value {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        _ => Err(invalid(field)),
    }
}

fn required_string(value: Option<&Value>, field: &str) -> Result<String, AuthError> {
    match value {
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(invalid(field)),
    }
}

fn invalid(field: &str) -> AuthError {
    AuthError::Storage(format!("invalid SQLite OAuth Provider row: {field}"))
}
