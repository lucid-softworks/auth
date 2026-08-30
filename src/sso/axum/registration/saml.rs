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
