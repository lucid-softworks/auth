#[cfg(any(feature = "axum", test))]
use super::SsoProvider;
#[cfg(any(feature = "axum", test))]
use base64::Engine as _;
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "axum", test))]
use serde_json::{Map, Value, json};
#[cfg(any(feature = "axum", test))]
use sha2::{Digest as _, Sha256};
#[cfg(any(feature = "axum", test))]
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoProviderReference {
    pub provider_id: String,
    pub source: SsoProviderSource,
    pub authentication_configuration_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SsoProviderSource {
    Configured,
    Persisted {
        #[serde(rename = "recordId")]
        record_id: String,
    },
}

#[cfg(feature = "axum")]
pub(super) type ProviderReference = SsoProviderReference;

#[cfg(any(feature = "axum", test))]
pub(super) fn persisted(provider: &SsoProvider) -> SsoProviderReference {
    SsoProviderReference {
        provider_id: provider.provider_id.clone(),
        source: SsoProviderSource::Persisted {
            record_id: provider.id.clone(),
        },
        authentication_configuration_fingerprint: fingerprint(provider),
    }
}

#[cfg(feature = "axum")]
pub(super) fn current(provider: &SsoProvider) -> SsoProviderReference {
    if provider.id == format!("default-sso:{}", provider.provider_id) {
        SsoProviderReference {
            provider_id: provider.provider_id.clone(),
            source: SsoProviderSource::Configured,
            authentication_configuration_fingerprint: fingerprint(provider),
        }
    } else {
        persisted(provider)
    }
}

#[cfg(feature = "axum")]
pub(super) fn parse(value: &Value) -> Option<SsoProviderReference> {
    serde_json::from_value(value.clone()).ok()
}

#[cfg(feature = "axum")]
impl SsoProviderReference {
    pub(super) fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub(super) fn is_current(&self, provider: &SsoProvider) -> bool {
        self == &current(provider)
    }
}

#[cfg(any(feature = "axum", test))]
fn fingerprint(provider: &SsoProvider) -> String {
    let mut authentication = Map::new();
    authentication.insert("domain".into(), json!(provider.domain));
    if let Some(verified) = provider.domain_verified {
        authentication.insert("domainVerified".into(), json!(verified));
    }
    authentication.insert("issuer".into(), json!(provider.issuer));
    authentication.insert("organizationId".into(), json!(provider.organization_id));
    if let Some(config) = provider.oidc_config.as_ref() {
        authentication.insert("oidcConfig".into(), without_oidc_secret(config));
    }
    if let Some(config) = provider.saml_config.as_ref() {
        authentication.insert("samlConfig".into(), without_saml_private_keys(config));
    }
    let canonical = canonical(&Value::Object(authentication));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(any(feature = "axum", test))]
fn without_oidc_secret(config: &Value) -> Value {
    let mut config = config.as_object().cloned().unwrap_or_default();
    config.remove("clientSecret");
    Value::Object(config)
}

#[cfg(any(feature = "axum", test))]
fn without_saml_private_keys(config: &Value) -> Value {
    let mut config = config.as_object().cloned().unwrap_or_default();
    config.remove("privateKey");
    let mut idp = config
        .get("idpMetadata")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    remove_nested_private_keys(&mut idp);
    config.insert("idpMetadata".into(), Value::Object(idp));
    if let Some(mut sp) = config
        .get("spMetadata")
        .and_then(Value::as_object)
        .cloned()
    {
        remove_nested_private_keys(&mut sp);
        config.insert("spMetadata".into(), Value::Object(sp));
    } else {
        config.remove("spMetadata");
    }
    Value::Object(config)
}

#[cfg(any(feature = "axum", test))]
fn remove_nested_private_keys(config: &mut Map<String, Value>) {
    for field in [
        "privateKey",
        "privateKeyPass",
        "encPrivateKey",
        "encPrivateKeyPass",
    ] {
        config.remove(field);
    }
}

#[cfg(any(feature = "axum", test))]
fn canonical(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("JSON string is serializable"),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Object(values) => {
            let sorted = values.iter().collect::<BTreeMap<_, _>>();
            let fields = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("JSON key is serializable"),
                        canonical(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}}}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> SsoProvider {
        SsoProvider {
            id: "row-17".into(),
            provider_id: "acme".into(),
            domain: "Example.COM, subsidiary.example.com".into(),
            domain_verified: Some(true),
            issuer: "https://idp.example.com".into(),
            organization_id: None,
            user_id: "owner".into(),
            oidc_config: Some(json!({
                "clientId": "client",
                "clientSecret": "never-hash-me",
                "pkce": true,
                "scopes": ["openid", "email"],
                "mapping": {"email": "mail", "nested": {"z": 2, "a": 1}}
            })),
            saml_config: Some(json!({
                "privateKey": "never-hash-me",
                "cert": "certificate",
                "idpMetadata": {
                    "entityID": "idp",
                    "privateKey": "never",
                    "encPrivateKey": "never",
                    "other": "kept"
                },
                "spMetadata": {"entityID": "sp", "privateKey": "never", "other": "kept"}
            })),
            additional_fields: serde_json::Map::new(),
        }
    }

    #[test]
    fn fingerprint_matches_the_pinned_node_oracle() {
        let reference = persisted(&provider());
        assert_eq!(reference.provider_id, "acme");
        assert_eq!(
            reference.authentication_configuration_fingerprint,
            "4hrr4Lx93A0e3CyE7EdOgfsnuWA1uzCu6q77fMe5mk4"
        );
        assert_eq!(
            serde_json::to_value(reference).unwrap()["source"],
            json!({"type": "persisted", "recordId": "row-17"})
        );
    }

    #[test]
    fn secrets_do_not_change_the_fingerprint_but_trust_configuration_does() {
        let baseline = fingerprint(&provider());
        let mut changed_secrets = provider();
        changed_secrets.oidc_config.as_mut().unwrap()["clientSecret"] = json!("changed");
        changed_secrets.saml_config.as_mut().unwrap()["privateKey"] = json!("changed");
        changed_secrets.saml_config.as_mut().unwrap()["idpMetadata"]["encPrivateKey"] =
            json!("changed");
        assert_eq!(fingerprint(&changed_secrets), baseline);

        let mut changed_trust = provider();
        changed_trust.saml_config.as_mut().unwrap()["cert"] = json!("new certificate");
        assert_ne!(fingerprint(&changed_trust), baseline);
    }

    #[cfg(feature = "axum")]
    #[test]
    fn configured_providers_have_no_persisted_record_identity() {
        let mut provider = provider();
        provider.id = "default-sso:acme".into();
        let reference = current(&provider);
        assert_eq!(
            serde_json::to_value(reference).unwrap()["source"],
            json!({"type": "configured"})
        );
    }
}
