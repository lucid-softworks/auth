use crate::{
    AgentAuthConfig, AgentAuthStore, AgentHost,
    agent_auth::{
        axum::host::error::{HostError, store_error},
        policy::find_blocked_capabilities,
    },
};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) async fn find_host_by_key(
    store: &Arc<dyn AgentAuthStore>,
    public_key: &Value,
) -> Result<Option<AgentHost>, HostError> {
    if let Some(kid) = public_key.get("kid").and_then(Value::as_str)
        && let Some(host) = store.find_host_by_kid(kid).await.map_err(store_error)?
    {
        return Ok(Some(host));
    }
    let serialized =
        serde_json::to_string(public_key).map_err(|_| HostError::invalid_public_key())?;
    store
        .find_host_by_public_key(&serialized)
        .await
        .map_err(store_error)
}

pub(super) fn validate_public_key(
    key: &Value,
    config: &AgentAuthConfig,
) -> Result<String, HostError> {
    let object = key.as_object().ok_or_else(HostError::invalid_public_key)?;
    if object.values().any(|value| match value {
        Value::String(_) | Value::Bool(_) => false,
        Value::Array(values) => !values.iter().all(Value::is_string),
        _ => true,
    }) {
        return Err(HostError::invalid_public_key());
    }
    let kty = object
        .get("kty")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(HostError::invalid_public_key)?;
    object
        .get("x")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(HostError::invalid_public_key)?;
    let algorithm = object.get("crv").and_then(Value::as_str).unwrap_or(kty);
    if !config
        .allowed_key_algorithms
        .iter()
        .any(|allowed| allowed == algorithm)
    {
        return Err(HostError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_algorithm",
            format!(
                "Key algorithm \"{algorithm}\" is not allowed. Accepted: {}",
                config.allowed_key_algorithms.join(", ")
            ),
        ));
    }
    serde_json::to_string(key).map_err(|_| HostError::invalid_public_key())
}

pub(super) fn validate_jwks_url(value: Option<&str>) -> Result<(), HostError> {
    if value.is_some_and(|value| url::Url::parse(value).is_err()) {
        return Err(HostError::invalid_request("Invalid url"));
    }
    Ok(())
}

pub(super) async fn validate_capabilities(
    values: &[String],
    config: &AgentAuthConfig,
) -> Result<(), HostError> {
    let blocked = find_blocked_capabilities(values, &config.blocked_capabilities);
    if !blocked.is_empty() {
        return Err(HostError::new(
            StatusCode::BAD_REQUEST,
            "capability_blocked",
            format!("Blocked capabilities: {}", blocked.join(", ")),
        ));
    }
    if !config.capabilities.is_empty() {
        let unknown: Vec<_> = values
            .iter()
            .filter(|value| {
                !config
                    .capabilities
                    .iter()
                    .any(|known| known.name == value.as_str())
            })
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(HostError::with_extra(
                StatusCode::BAD_REQUEST,
                "invalid_capabilities",
                "One or more requested capability names don't exist or are blocked",
                json!({"invalid_capabilities": unknown}),
            ));
        }
    }
    if let Some(validate) = &config.validate_capabilities
        && !validate.validate(values.to_vec()).await
    {
        return Err(HostError::new(
            StatusCode::BAD_REQUEST,
            "invalid_capabilities",
            "One or more requested capability names don't exist or are blocked",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::agent_auth::jwt::jwk_thumbprint;
    use serde_json::json;

    #[test]
    fn jwk_thumbprint_ignores_non_thumbprint_members() {
        assert_eq!(
            jwk_thumbprint(&json!({"kty":"OKP","crv":"Ed25519","x":"public-key","kid":"ignored"}))
                .unwrap(),
            jwk_thumbprint(&json!({"x":"public-key","crv":"Ed25519","kty":"OKP"})).unwrap()
        );
    }
}
