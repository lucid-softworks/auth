use serde_json::{Map, Value};

pub(super) fn normalize_metadata(raw: &Value) -> Result<Map<String, Value>, String> {
    let raw = raw
        .as_object()
        .ok_or_else(|| "metadata document is not a JSON object".to_owned())?;
    if let Some(field) = raw.keys().find(|field| is_forbidden_server_field(field)) {
        return Err(format!("metadata document MUST NOT contain \"{field}\""));
    }
    let mut metadata = raw
        .iter()
        .filter(|(name, _)| is_metadata_field(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Map<_, _>>();
    validate_shape(&mut metadata)?;
    Ok(metadata)
}

fn validate_shape(metadata: &mut Map<String, Value>) -> Result<(), String> {
    require_nonempty_string(metadata, "client_id", true)?;
    for field in [
        "scope", "client_name", "client_uri", "logo_uri", "tos_uri", "policy_uri",
        "software_id", "software_version", "software_statement", "jwks_uri",
    ] {
        require_string(metadata, field)?;
    }
    require_string_array(metadata, "contacts", true, true)?;
    require_string_array(metadata, "redirect_uris", true, false)?;
    require_string_array(metadata, "post_logout_redirect_uris", true, false)?;
    require_trimmed_string(metadata, "token_endpoint_auth_method")?;
    require_trimmed_string_array(metadata, "grant_types", true)?;
    require_enum_array(metadata, "response_types", &["code"])?;
    require_enum(metadata, "application_type", &["web", "native"])?;
    require_enum(metadata, "subject_type", &["public", "pairwise"])?;
    require_boolean(metadata, "dpop_bound_access_tokens")?;
    reject_backchannel_logout(metadata)?;
    normalize_jwks(metadata)
}

fn reject_backchannel_logout(metadata: &Map<String, Value>) -> Result<(), String> {
    for field in [
        "backchannel_logout_uri",
        "backchannel_logout_session_required",
    ] {
        if metadata.contains_key(field) {
            return Err(format!("metadata document MUST NOT contain \"{field}\""));
        }
    }
    Ok(())
}

fn normalize_jwks(metadata: &mut Map<String, Value>) -> Result<(), String> {
    let Some(jwks) = metadata.get_mut("jwks") else {
        return Ok(());
    };
    let Some(object) = jwks.as_object_mut() else {
        return Err("jwks: Invalid input: expected object, received non-object".into());
    };
    if !object.get("keys").is_some_and(Value::is_array) {
        return Err("jwks.keys: Invalid input: expected array, received undefined".into());
    }
    object.retain(|name, _| name == "keys");
    Ok(())
}

fn is_metadata_field(field: &str) -> bool {
    matches!(
        field,
        "client_id" | "redirect_uris" | "scope" | "client_name" | "client_uri"
            | "logo_uri" | "contacts" | "tos_uri" | "policy_uri" | "software_id"
            | "software_version" | "software_statement" | "post_logout_redirect_uris"
            | "backchannel_logout_uri" | "backchannel_logout_session_required"
            | "token_endpoint_auth_method" | "jwks" | "jwks_uri" | "grant_types"
            | "response_types" | "application_type" | "subject_type"
            | "dpop_bound_access_tokens"
    )
}

fn is_forbidden_server_field(field: &str) -> bool {
    matches!(
        field,
        "disabled" | "client_secret" | "client_secret_expires_at" | "client_id_issued_at"
            | "skip_consent" | "enable_end_session" | "require_pkce" | "reference_id"
            | "user_id" | "resources" | "clientSecret" | "clientDiscoveryId"
            | "skipConsent" | "enableEndSession" | "requirePKCE" | "referenceId"
            | "userId" | "clientId" | "applicationType" | "tokenEndpointAuthMethod"
            | "redirectUris" | "postLogoutRedirectUris" | "grantTypes" | "responseTypes"
            | "scopes" | "expiresAt" | "createdAt" | "updatedAt" | "softwareId"
            | "softwareVersion" | "softwareStatement" | "backchannelLogoutUri"
            | "backchannelLogoutSessionRequired" | "jwksUri" | "dpopBoundAccessTokens"
            | "subjectType"
    )
}

fn require_string(metadata: &Map<String, Value>, field: &str) -> Result<(), String> {
    if metadata.get(field).is_some_and(|value| !value.is_string()) {
        return Err(format!(
            "{field}: Invalid input: expected string, received non-string"
        ));
    }
    Ok(())
}

fn require_nonempty_string(
    metadata: &Map<String, Value>, field: &str, required: bool,
) -> Result<(), String> {
    match metadata.get(field).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(()),
        None if !required && !metadata.contains_key(field) => Ok(()),
        None if required && !metadata.contains_key(field) => Err(format!("{field}: required")),
        _ => Err(format!("{field}: invalid string")),
    }
}

fn require_trimmed_string(metadata: &mut Map<String, Value>, field: &str) -> Result<(), String> {
    let Some(value) = metadata.get_mut(field) else { return Ok(()); };
    let Some(string) = value.as_str() else { return Err(format!("{field}: invalid string")); };
    let trimmed = string.trim();
    if trimmed.is_empty() { return Err(format!("{field}: invalid string")); }
    *value = Value::String(trimmed.into());
    Ok(())
}

fn require_string_array(
    metadata: &Map<String, Value>, field: &str, nonempty: bool, nonempty_items: bool,
) -> Result<(), String> {
    let Some(value) = metadata.get(field) else { return Ok(()); };
    let Some(values) = value.as_array() else { return Err(format!("{field}: invalid array")); };
    if (nonempty && values.is_empty()) || values.iter().any(|value| {
        value.as_str().is_none_or(|value| nonempty_items && value.is_empty())
    }) {
        return Err(format!("{field}: invalid array"));
    }
    Ok(())
}

fn require_trimmed_string_array(
    metadata: &mut Map<String, Value>, field: &str, nonempty: bool,
) -> Result<(), String> {
    let Some(value) = metadata.get_mut(field) else { return Ok(()); };
    let Some(values) = value.as_array_mut() else { return Err(format!("{field}: invalid array")); };
    if nonempty && values.is_empty() { return Err(format!("{field}: invalid array")); }
    for value in values {
        let Some(string) = value.as_str() else { return Err(format!("{field}: invalid array")); };
        let trimmed = string.trim();
        if trimmed.is_empty() { return Err(format!("{field}: invalid array")); }
        *value = Value::String(trimmed.into());
    }
    Ok(())
}

fn require_enum(
    metadata: &Map<String, Value>, field: &str, allowed: &[&str],
) -> Result<(), String> {
    if metadata.get(field).is_some_and(|value| {
        value.as_str().is_none_or(|value| !allowed.contains(&value))
    }) { return Err(format!("{field}: invalid value")); }
    Ok(())
}

fn require_enum_array(
    metadata: &Map<String, Value>, field: &str, allowed: &[&str],
) -> Result<(), String> {
    if metadata.get(field).is_some_and(|value| value.as_array().is_none_or(|values| {
        values.iter().any(|value| value.as_str().is_none_or(|value| !allowed.contains(&value)))
    })) { return Err(format!("{field}: invalid value")); }
    Ok(())
}

fn require_boolean(metadata: &Map<String, Value>, field: &str) -> Result<(), String> {
    if metadata.get(field).is_some_and(|value| !value.is_boolean()) {
        return Err(format!("{field}: invalid boolean"));
    }
    Ok(())
}
