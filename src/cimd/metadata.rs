use super::{
    jwks::validate_public_jwks,
    schema::normalize_metadata,
    uri::{client_id_warnings, validate_document_uris},
};
use serde_json::{Map, Value};

pub type CimdMetadata = Map<String, Value>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CimdMetadataProfile {
    Mcp20260728,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimdMetadataValidationOptions {
    pub origin_bound_fields: Vec<String>,
    pub metadata_profile: Option<CimdMetadataProfile>,
}

impl Default for CimdMetadataValidationOptions {
    fn default() -> Self {
        Self {
            origin_bound_fields: vec!["post_logout_redirect_uris".into(), "client_uri".into()],
            metadata_profile: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CimdMetadataValidationResult {
    Valid {
        metadata: CimdMetadata,
        warnings: Vec<String>,
    },
    Invalid {
        error: String,
        warnings: Vec<String>,
    },
}

impl CimdMetadataValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    pub fn metadata(&self) -> Option<&CimdMetadata> {
        match self {
            Self::Valid { metadata, .. } => Some(metadata),
            Self::Invalid { .. } => None,
        }
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            Self::Valid { .. } => None,
            Self::Invalid { error, .. } => Some(error),
        }
    }

    pub fn warnings(&self) -> &[String] {
        match self {
            Self::Valid { warnings, .. } | Self::Invalid { warnings, .. } => warnings,
        }
    }
}

pub fn validate_cimd_metadata(
    client_id_url: &str,
    raw: &Value,
    options: &CimdMetadataValidationOptions,
) -> CimdMetadataValidationResult {
    let mut metadata = match normalize_metadata(raw) {
        Ok(metadata) => metadata,
        Err(error) => return invalid(error),
    };
    if let Err(error) = validate_protocol(client_id_url, &metadata, options) {
        return invalid(error);
    }
    if let Err(error) = validate_document_uris(client_id_url, &metadata, options) {
        return invalid(error);
    }
    metadata
        .entry("token_endpoint_auth_method")
        .or_insert_with(|| Value::String("none".into()));
    CimdMetadataValidationResult::Valid {
        metadata,
        warnings: client_id_warnings(client_id_url),
    }
}

fn validate_protocol(
    client_id_url: &str,
    metadata: &CimdMetadata,
    options: &CimdMetadataValidationOptions,
) -> Result<(), String> {
    if metadata.get("client_id").and_then(Value::as_str) != Some(client_id_url) {
        return Err(format!(
            "client_id \"{}\" does not match the metadata document URL",
            display_value(metadata.get("client_id"))
        ));
    }
    validate_profile(metadata, options.metadata_profile)?;
    validate_authentication(metadata)?;
    if metadata
        .get("jwks")
        .is_some_and(|jwks| !validate_public_jwks(jwks))
    {
        return Err("jwks must contain only structurally valid public keys".into());
    }
    Ok(())
}

fn validate_profile(
    metadata: &CimdMetadata,
    profile: Option<CimdMetadataProfile>,
) -> Result<(), String> {
    if profile != Some(CimdMetadataProfile::Mcp20260728) {
        return Ok(());
    }
    if metadata
        .get("client_name")
        .and_then(Value::as_str)
        .is_none_or(|name| name.trim().is_empty())
    {
        return Err("client_name must be a non-empty string".into());
    }
    if metadata
        .get("redirect_uris")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        return Err(
            "redirect_uris must be a non-empty array of absolute HTTP(S) or private-use URIs"
                .into(),
        );
    }
    Ok(())
}

fn validate_authentication(metadata: &CimdMetadata) -> Result<(), String> {
    let Some(method) = metadata
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    if matches!(
        method,
        "client_secret_post" | "client_secret_basic" | "client_secret_jwt"
    ) {
        return Err(format!(
            "symmetric auth method \"{method}\" is prohibited for Client ID Metadata Document clients"
        ));
    }
    if !matches!(method, "none" | "private_key_jwt") {
        return Err(
            "token_endpoint_auth_method must be \"none\" or \"private_key_jwt\" for Client ID Metadata Document clients"
                .into(),
        );
    }
    if method == "private_key_jwt"
        && !metadata.contains_key("jwks")
        && !metadata.contains_key("jwks_uri")
    {
        return Err(
            "private_key_jwt requires either jwks or jwks_uri in the metadata document".into(),
        );
    }
    Ok(())
}

fn display_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(value) => value.to_string(),
        None => "undefined".into(),
    }
}

fn invalid(error: impl Into<String>) -> CimdMetadataValidationResult {
    CimdMetadataValidationResult::Invalid {
        error: error.into(),
        warnings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn validate(raw: Value) -> CimdMetadataValidationResult {
        validate_cimd_metadata(
            "https://client.example/metadata.json",
            &raw,
            &CimdMetadataValidationOptions::default(),
        )
    }

    #[test]
    fn generic_profile_defaults_auth_and_strips_unknown_fields() {
        let result = validate(json!({
            "client_id": "https://client.example/metadata.json",
            "future_extension": true
        }));
        let metadata = result.metadata().unwrap();
        assert_eq!(metadata.get("token_endpoint_auth_method"), Some(&json!("none")));
        assert!(!metadata.contains_key("future_extension"));
    }

    #[test]
    fn mcp_profile_requires_name_and_redirects() {
        let options = CimdMetadataValidationOptions {
            metadata_profile: Some(CimdMetadataProfile::Mcp20260728),
            ..Default::default()
        };
        let result = validate_cimd_metadata(
            "https://client.example/metadata.json",
            &json!({"client_id": "https://client.example/metadata.json"}),
            &options,
        );
        assert_eq!(result.error(), Some("client_name must be a non-empty string"));
    }

    #[test]
    fn rejects_server_fields_secret_auth_and_cross_origin_claims() {
        assert!(validate(json!({
            "client_id": "https://client.example/metadata.json", "skipConsent": true
        })).error().unwrap().contains("skipConsent"));
        assert!(validate(json!({
            "client_id": "https://client.example/metadata.json",
            "token_endpoint_auth_method": "client_secret_basic"
        })).error().unwrap().contains("symmetric auth method"));
        assert!(validate(json!({
            "client_id": "https://client.example/metadata.json",
            "client_uri": "https://other.example/client"
        })).error().unwrap().contains("same origin"));
    }

    #[test]
    fn validates_redirect_and_key_material_profiles() {
        assert!(validate(json!({
            "client_id": "https://client.example/metadata.json",
            "redirect_uris": ["com.example.app:/callback", "https://app.example/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [{"kty": "RSA", "n": "n", "e": "AQAB"}]}
        })).is_valid());
        assert!(!validate(json!({
            "client_id": "https://client.example/metadata.json",
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [{"kty": "oct", "k": "secret"}]}
        })).is_valid());
    }
}
