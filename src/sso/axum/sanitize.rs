use super::super::SsoProvider;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Map, Value, json};

const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

pub(super) fn provider(provider: &SsoProvider, base_url: &str) -> Value {
    let mut output = Map::new();
    output.insert("providerId".into(), json!(provider.provider_id));
    output.insert(
        "type".into(),
        json!(if provider.saml_config.is_some() {
            "saml"
        } else {
            "oidc"
        }),
    );
    output.insert("issuer".into(), json!(provider.issuer));
    output.insert("domain".into(), json!(provider.domain));
    output.insert("organizationId".into(), json!(provider.organization_id));
    output.insert(
        "domainVerified".into(),
        json!(provider.domain_verified.unwrap_or(false)),
    );
    if let Some(config) = provider.oidc_config.as_ref().and_then(Value::as_object) {
        output.insert("oidcConfig".into(), oidc(config));
    }
    if let Some(config) = provider.saml_config.as_ref().and_then(Value::as_object) {
        output.insert("samlConfig".into(), saml(config));
    }
    output.insert(
        "spMetadataUrl".into(),
        json!(format!(
            "{}/sso/saml2/sp/metadata?providerId={}",
            base_url.trim_end_matches('/'),
            utf8_percent_encode(&provider.provider_id, URI_COMPONENT)
        )),
    );
    Value::Object(output)
}

fn oidc(config: &Map<String, Value>) -> Value {
    let mut output = Map::new();
    copy(config, &mut output, "discoveryEndpoint");
    if let Some(client_id) = config.get("clientId").and_then(Value::as_str) {
        output.insert("clientIdLastFour".into(), json!(mask_client_id(client_id)));
    }
    for field in [
        "pkce",
        "authorizationEndpoint",
        "tokenEndpoint",
        "userInfoEndpoint",
        "jwksEndpoint",
        "scopes",
        "tokenEndpointAuthentication",
    ] {
        copy(config, &mut output, field);
    }
    Value::Object(output)
}

fn saml(config: &Map<String, Value>) -> Value {
    let mut output = Map::new();
    for field in [
        "entryPoint",
        "callbackUrl",
        "idpInitiatedCallbackUrl",
        "audience",
        "wantAssertionsSigned",
        "authnRequestsSigned",
        "identifierFormat",
        "signatureAlgorithm",
        "digestAlgorithm",
    ] {
        copy(config, &mut output, field);
    }
    Value::Object(output)
}

fn mask_client_id(client_id: &str) -> String {
    if client_id.chars().count() <= 4 {
        return "****".into();
    }
    let suffix = client_id.chars().rev().take(4).collect::<Vec<_>>();
    format!("****{}", suffix.into_iter().rev().collect::<String>())
}

fn copy(source: &Map<String, Value>, target: &mut Map<String, Value>, field: &str) {
    if let Some(value) = source.get(field) {
        target.insert(field.into(), value.clone());
    }
}
