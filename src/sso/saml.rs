mod algorithms;

pub use algorithms::{
    DataEncryptionAlgorithm, DigestAlgorithm, KeyEncryptionAlgorithm, SignatureAlgorithm,
};
#[cfg(any(feature = "axum", test))]
use algorithms::{normalize_digest, normalize_signature, secure_digests, secure_signatures};
#[cfg(any(feature = "axum", test))]
use serde_json::Map;
#[cfg(any(feature = "axum", test))]
use serde_json::Value;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeprecatedAlgorithmBehavior {
    Reject,
    #[default]
    Warn,
    Allow,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SamlAlgorithmOptions {
    pub on_deprecated: DeprecatedAlgorithmBehavior,
    pub allowed_signature_algorithms: Option<Vec<String>>,
    pub allowed_digest_algorithms: Option<Vec<String>>,
    pub allowed_key_encryption_algorithms: Option<Vec<String>>,
    pub allowed_data_encryption_algorithms: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SamlAlgorithmError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamlServiceProviderPolicy {
    pub want_assertions_signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SamlConfigurationError {
    #[error("Invalid SAML service provider metadata")]
    InvalidServiceProviderMetadata,
    #[error("Invalid SAML identity provider metadata")]
    InvalidIdentityProviderMetadata,
    #[error("SAML manual IdP configuration requires idpMetadata.entityID")]
    MissingIdentityProviderEntityId,
}

#[cfg(feature = "axum")]
pub fn derive_saml_service_provider_policy(
    config: &Value,
) -> Result<SamlServiceProviderPolicy, SamlConfigurationError> {
    use samlet::raw::{Binding, metadata::SpMetadata};

    let config = config
        .as_object()
        .ok_or(SamlConfigurationError::InvalidServiceProviderMetadata)?;
    let configured = config
        .get("wantAssertionsSigned")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let Some(metadata) = config
        .get("spMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("metadata"))
        .and_then(Value::as_str)
    else {
        return Ok(SamlServiceProviderPolicy {
            want_assertions_signed: configured,
        });
    };
    let metadata = SpMetadata::from_xml(metadata)
        .map_err(|_| SamlConfigurationError::InvalidServiceProviderMetadata)?;
    if metadata
        .get_assertion_consumer_service(Binding::Post)
        .is_none()
    {
        return Err(SamlConfigurationError::InvalidServiceProviderMetadata);
    }
    Ok(SamlServiceProviderPolicy {
        want_assertions_signed: metadata.is_want_assertions_signed(),
    })
}

#[cfg(feature = "axum")]
pub fn derive_saml_identity_provider_entity_id(
    config: &Value,
) -> Result<String, SamlConfigurationError> {
    use samlet::raw::metadata::IdpMetadata;

    let idp = config
        .get("idpMetadata")
        .and_then(Value::as_object)
        .ok_or(SamlConfigurationError::MissingIdentityProviderEntityId)?;
    if let Some(metadata) = idp.get("metadata").and_then(Value::as_str) {
        return IdpMetadata::from_xml(metadata)
            .ok()
            .and_then(|metadata| metadata.get_entity_id().map(str::to_owned))
            .filter(|entity_id| !entity_id.is_empty())
            .ok_or(SamlConfigurationError::InvalidIdentityProviderMetadata);
    }
    idp.get("entityID")
        .and_then(Value::as_str)
        .filter(|entity_id| !entity_id.is_empty())
        .map(str::to_owned)
        .ok_or(SamlConfigurationError::MissingIdentityProviderEntityId)
}

#[cfg(any(feature = "axum", test))]
pub(crate) fn validate_configuration_algorithms(
    config: &Map<String, Value>,
    options: &SamlAlgorithmOptions,
) -> Result<(), SamlAlgorithmError> {
    if let Some(algorithm) = config.get("signatureAlgorithm").and_then(Value::as_str) {
        validate_config_algorithm(
            algorithm,
            &options.allowed_signature_algorithms,
            normalize_signature,
            SignatureAlgorithm::RSA_SHA1,
            secure_signatures(),
            options.on_deprecated,
            "signature",
        )?;
    }
    if let Some(algorithm) = config.get("digestAlgorithm").and_then(Value::as_str) {
        validate_config_algorithm(
            algorithm,
            &options.allowed_digest_algorithms,
            normalize_digest,
            DigestAlgorithm::SHA1,
            secure_digests(),
            options.on_deprecated,
            "digest",
        )?;
    }
    Ok(())
}

#[cfg(feature = "axum")]
pub(crate) fn validate_response_algorithms(
    session: &samlet::SsoSession,
    options: &SamlAlgorithmOptions,
) -> Result<(), SamlAlgorithmError> {
    if let Some(algorithm) = session.sig_alg() {
        validate_response_signature(algorithm, options)?;
    }
    validate_encryption_algorithms(&session.raw_flow().saml_content, options)
}

#[cfg(feature = "axum")]
fn validate_response_signature(
    algorithm: &str,
    options: &SamlAlgorithmOptions,
) -> Result<(), SamlAlgorithmError> {
    if let Some(allowed) = options.allowed_signature_algorithms.as_ref() {
        return allowed
            .iter()
            .any(|candidate| candidate == algorithm)
            .then_some(())
            .ok_or_else(|| not_allowed("signature", algorithm));
    }
    if algorithm == SignatureAlgorithm::RSA_SHA1 {
        return deprecated(
            options.on_deprecated,
            format!("SAML response uses deprecated signature algorithm: {algorithm}. Please configure your IdP to use SHA-256 or stronger."),
        );
    }
    secure_signatures()
        .contains(&algorithm)
        .then_some(())
        .ok_or_else(|| unknown("signature", algorithm))
}

#[cfg(feature = "axum")]
fn validate_encryption_algorithms(
    xml: &str,
    options: &SamlAlgorithmOptions,
) -> Result<(), SamlAlgorithmError> {
    let roots = samlet::xml::dom::parse_roots(xml).map_err(|_| unknown("encryption", "XML"))?;
    let (key, data) = roots
        .iter()
        .fold((None, None), |found, node| encryption_algorithms(node, found));
    validate_encryption_algorithm(
        key,
        options.allowed_key_encryption_algorithms.as_ref(),
        KeyEncryptionAlgorithm::RSA_1_5,
        options.on_deprecated,
        "key encryption",
    )?;
    validate_encryption_algorithm(
        data,
        options.allowed_data_encryption_algorithms.as_ref(),
        DataEncryptionAlgorithm::TRIPLEDES_CBC,
        options.on_deprecated,
        "data encryption",
    )
}

#[cfg(feature = "axum")]
fn encryption_algorithms<'a>(
    node: &'a samlet::xml::dom::Node,
    mut found: (Option<&'a str>, Option<&'a str>),
) -> (Option<&'a str>, Option<&'a str>) {
    if node.local_name == "EncryptedKey" {
        found.0 = node
            .children
            .iter()
            .find(|child| child.local_name == "EncryptionMethod")
            .and_then(|method| method.attr("Algorithm"));
    } else if node.local_name == "EncryptedData" {
        found.1 = node
            .children
            .iter()
            .find(|child| child.local_name == "EncryptionMethod")
            .and_then(|method| method.attr("Algorithm"));
    }
    node.children
        .iter()
        .fold(found, |found, child| encryption_algorithms(child, found))
}

#[cfg(feature = "axum")]
fn validate_encryption_algorithm(
    algorithm: Option<&str>,
    allowed: Option<&Vec<String>>,
    deprecated_algorithm: &str,
    behavior: DeprecatedAlgorithmBehavior,
    kind: &str,
) -> Result<(), SamlAlgorithmError> {
    let Some(algorithm) = algorithm else {
        return Ok(());
    };
    if let Some(allowed) = allowed {
        return allowed
            .iter()
            .any(|candidate| candidate == algorithm)
            .then_some(())
            .ok_or_else(|| not_allowed(kind, algorithm));
    }
    if algorithm == deprecated_algorithm {
        return deprecated(
            behavior,
            format!("SAML response uses deprecated {kind} algorithm: {algorithm}."),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(feature = "axum", test))]
fn validate_config_algorithm(
    algorithm: &str,
    allowed: &Option<Vec<String>>,
    normalize: fn(&str) -> &str,
    deprecated_algorithm: &str,
    secure: &[&str],
    behavior: DeprecatedAlgorithmBehavior,
    kind: &str,
) -> Result<(), SamlAlgorithmError> {
    let normalized = normalize(algorithm);
    if let Some(allowed) = allowed {
        return allowed
            .iter()
            .map(|candidate| normalize(candidate))
            .any(|candidate| candidate == normalized)
            .then_some(())
            .ok_or_else(|| not_allowed(kind, algorithm));
    }
    if normalized == deprecated_algorithm {
        return deprecated_config(
            behavior,
            format!("SAML config uses deprecated {kind} algorithm: {algorithm}. Consider using SHA-256 or stronger."),
        );
    }
    secure
        .contains(&normalized)
        .then_some(())
        .ok_or_else(|| unknown(kind, algorithm))
}

#[cfg(any(feature = "axum", test))]
fn deprecated(
    behavior: DeprecatedAlgorithmBehavior,
    message: String,
) -> Result<(), SamlAlgorithmError> {
    match behavior {
        DeprecatedAlgorithmBehavior::Reject => Err(SamlAlgorithmError {
            code: "SAML_DEPRECATED_ALGORITHM",
            message,
        }),
        DeprecatedAlgorithmBehavior::Warn => {
            tracing::warn!(message = %message, "deprecated SAML algorithm");
            Ok(())
        }
        DeprecatedAlgorithmBehavior::Allow => Ok(()),
    }
}

#[cfg(any(feature = "axum", test))]
fn deprecated_config(
    behavior: DeprecatedAlgorithmBehavior,
    message: String,
) -> Result<(), SamlAlgorithmError> {
    deprecated(behavior, message).map_err(|mut error| {
        error.code = "SAML_DEPRECATED_CONFIG_ALGORITHM";
        error
    })
}

#[cfg(any(feature = "axum", test))]
fn not_allowed(kind: &str, algorithm: &str) -> SamlAlgorithmError {
    SamlAlgorithmError {
        code: "SAML_ALGORITHM_NOT_ALLOWED",
        message: format!("SAML {kind} algorithm not in allow-list: {algorithm}"),
    }
}

#[cfg(any(feature = "axum", test))]
fn unknown(kind: &str, algorithm: &str) -> SamlAlgorithmError {
    SamlAlgorithmError {
        code: "SAML_UNKNOWN_ALGORITHM",
        message: format!("SAML {kind} algorithm not recognized: {algorithm}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn configuration_short_forms_match_the_pinned_algorithm_policy() {
        let mut options = SamlAlgorithmOptions {
            allowed_signature_algorithms: Some(vec![SignatureAlgorithm::RSA_SHA256.into()]),
            allowed_digest_algorithms: Some(vec![DigestAlgorithm::SHA256.into()]),
            ..SamlAlgorithmOptions::default()
        };
        validate_configuration_algorithms(
            json!({"signatureAlgorithm": "sha256", "digestAlgorithm": "sha256"})
                .as_object()
                .unwrap(),
            &options,
        )
        .unwrap();
        options.on_deprecated = DeprecatedAlgorithmBehavior::Reject;
        let error = validate_configuration_algorithms(
            json!({"signatureAlgorithm": "sha512", "digestAlgorithm": "sha256"})
                .as_object()
                .unwrap(),
            &options,
        )
        .unwrap_err();
        assert_eq!(error.code, "SAML_ALGORITHM_NOT_ALLOWED");

        options.allowed_signature_algorithms = None;
        let error = validate_configuration_algorithms(
            json!({"signatureAlgorithm": "sha1"})
                .as_object()
                .unwrap(),
            &options,
        )
        .unwrap_err();
        assert_eq!(error.code, "SAML_DEPRECATED_CONFIG_ALGORITHM");
    }
}
