use axum::{http::StatusCode, response::Response};
use serde_json::{Map, Value, json};

pub(super) fn prepare(issuer: &str, config: &Value) -> Result<Value, Box<Response>> {
    let Some(config) = config.as_object() else {
        return Err(Box::new(super::super::support::error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid SAML configuration",
        )));
    };
    validate(config)?;
    let mut persisted = Map::new();
    persisted.insert("issuer".into(), json!(issuer));
    for field in [
        "entryPoint",
        "cert",
        "audience",
        "callbackUrl",
        "idpInitiatedCallbackUrl",
        "idpMetadata",
        "spMetadata",
        "wantAssertionsSigned",
        "authnRequestsSigned",
        "signatureAlgorithm",
        "digestAlgorithm",
        "identifierFormat",
        "privateKey",
        "mapping",
    ] {
        if let Some(value) = config.get(field) {
            persisted.insert(field.into(), value.clone());
        }
    }
    Ok(Value::Object(persisted))
}

fn validate(config: &Map<String, Value>) -> Result<(), Box<Response>> {
    validate_entry_point(config)?;
    validate_identity_provider(config)?;
    validate_redirects(config)?;
    validate_service_provider(config)?;
    Ok(())
}

fn validate_entry_point(config: &Map<String, Value>) -> Result<(), Box<Response>> {
    if config
        .get("entryPoint")
        .and_then(Value::as_str)
        .filter(|entry| url::Url::parse(entry).is_ok())
        .is_none()
    {
        return Err(Box::new(validation("Invalid SAML entryPoint URL")));
    }
    Ok(())
}

fn validate_identity_provider(config: &Map<String, Value>) -> Result<(), Box<Response>> {
    let idp = config
        .get("idpMetadata")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            Box::new(validation(
                "[body.samlConfig.idpMetadata] idpMetadata.entityID is required when IdP metadata XML is not provided",
            ))
        })?;
    let metadata = idp
        .get("metadata")
        .and_then(Value::as_str)
        .filter(|metadata| !metadata.is_empty());
    let entity_id = idp
        .get("entityID")
        .and_then(Value::as_str)
        .filter(|entity| !entity.is_empty());
    if metadata.is_none() && entity_id.is_none() {
        return Err(Box::new(validation(
            "[body.samlConfig.idpMetadata] idpMetadata.entityID is required when IdP metadata XML is not provided",
        )));
    }
    validate_metadata_size(metadata, "IdP")?;
    if metadata.is_none()
        && config.get("cert").is_none()
        && idp.get("cert").is_none()
    {
        return Err(Box::new(super::super::support::error(
            StatusCode::BAD_REQUEST,
            "CERT_SOURCE_MISSING",
            "samlConfig requires either a signing certificate (cert or idpMetadata.cert) or an idpMetadata.metadata XML document.",
        )));
    }
    Ok(())
}

fn validate_redirects(config: &Map<String, Value>) -> Result<(), Box<Response>> {
    if config
        .get("callbackUrl")
        .and_then(Value::as_str)
        .is_some_and(|callback| callback.contains('#'))
    {
        return Err(Box::new(validation(
            "[body.samlConfig.callbackUrl] callbackUrl must not contain a fragment",
        )));
    }
    if config
        .get("idpInitiatedCallbackUrl")
        .and_then(Value::as_str)
        .is_some_and(|callback| !callback.starts_with('/') && url::Url::parse(callback).is_err())
    {
        return Err(Box::new(validation(
            "[body.samlConfig.idpInitiatedCallbackUrl] Expected an absolute URL or a relative path starting with /",
        )));
    }
    Ok(())
}

fn validate_service_provider(config: &Map<String, Value>) -> Result<(), Box<Response>> {
    let sp_metadata = config
        .get("spMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("metadata"))
        .and_then(Value::as_str);
    validate_metadata_size(sp_metadata, "SP")?;
    if let Some(metadata) = sp_metadata {
        if !metadata.contains("EntityDescriptor")
            || !metadata.contains("AssertionConsumerService")
        {
            return Err(Box::new(super::super::support::error(
                StatusCode::BAD_REQUEST,
                "SAML_INVALID_SP_METADATA",
                "Invalid SAML service provider metadata",
            )));
        }
        if config.get("wantAssertionsSigned") == Some(&Value::Bool(true))
            && !metadata.contains("WantAssertionsSigned=\"true\"")
        {
            return Err(Box::new(super::super::support::error(
                StatusCode::BAD_REQUEST,
                "SAML_SP_METADATA_ASSERTION_SIGNATURE_MISMATCH",
                "SAML service provider metadata must require signed assertions",
            )));
        }
    }
    Ok(())
}

fn validate_metadata_size(metadata: Option<&str>, kind: &str) -> Result<(), Box<Response>> {
    if metadata.is_some_and(|metadata| {
        metadata.len() > crate::sso::DEFAULT_MAX_SAML_METADATA_SIZE
    }) {
        return Err(Box::new(super::super::support::error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            format!(
                "{kind} metadata exceeds maximum allowed size ({} bytes)",
                crate::sso::DEFAULT_MAX_SAML_METADATA_SIZE
            ),
        )));
    }
    Ok(())
}

fn validation(message: &'static str) -> Response {
    super::super::support::error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message)
}
