use crate::{AuthService, SsoProvider};
use samlet::raw::metadata::{Endpoint, IdpMetadataConfig, SpMetadata, SpMetadataConfig};
use samlet::raw::{Binding, EntitySetting, IdentityProvider, ServiceProvider};
use serde_json::{Map, Value};

pub(super) struct SamlEntities {
    pub(super) sp: ServiceProvider,
    pub(super) idp: IdentityProvider,
}

pub(super) fn entities(
    service: &AuthService,
    provider: &SsoProvider,
    config: &Map<String, Value>,
    options: &crate::SsoOptions,
) -> Result<SamlEntities, ()> {
    Ok(SamlEntities {
        sp: service_provider(service, provider, config, options)?,
        idp: identity_provider(config, options)?,
    })
}

fn service_provider(
    service: &AuthService,
    provider: &SsoProvider,
    config: &Map<String, Value>,
    options: &crate::SsoOptions,
) -> Result<ServiceProvider, ()> {
    let custom = nested_string(config, "spMetadata", "metadata")
        .map(SpMetadata::from_xml)
        .transpose()
        .map_err(|_| ())?;
    let entity_id = nested_string(config, "spMetadata", "entityID")
        .or_else(|| custom.as_ref().and_then(|metadata| metadata.get_entity_id()))
        .or_else(|| config.get("issuer").and_then(Value::as_str))
        .unwrap_or(&provider.issuer);
    let want_assertions_signed = config
        .get("wantAssertionsSigned")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || custom
            .as_ref()
            .is_some_and(SpMetadata::is_want_assertions_signed);
    let acs = format!(
        "{}/sso/saml2/sp/acs/{}",
        super::super::support::base_url(service),
        provider.provider_id
    );
    let mut setting = entity_setting(config, "spMetadata", options);
    setting.want_assertions_signed = want_assertions_signed;
    setting.validate_audience = true;
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: entity_id.into(),
            want_assertions_signed,
            authn_requests_signed: config
                .get("authnRequestsSigned")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, acs)],
            ..Default::default()
        },
        setting,
    )
    .map_err(|_| ())
}

fn identity_provider(
    config: &Map<String, Value>,
    options: &crate::SsoOptions,
) -> Result<IdentityProvider, ()> {
    let idp = config
        .get("idpMetadata")
        .and_then(Value::as_object)
        .ok_or(())?;
    let setting = entity_setting(config, "idpMetadata", options);
    if let Some(metadata) = idp.get("metadata").and_then(Value::as_str) {
        return IdentityProvider::from_metadata(metadata, setting).map_err(|_| ());
    }
    let entity_id = idp.get("entityID").and_then(Value::as_str).ok_or(())?;
    let entry_point = config.get("entryPoint").and_then(Value::as_str).ok_or(())?;
    let signing_certs = idp
        .get("cert")
        .or_else(|| config.get("cert"))
        .map(certificates)
        .unwrap_or_default();
    if signing_certs.is_empty() {
        return Err(());
    }
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: entity_id.into(),
            signing_certs,
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, entry_point)],
            ..Default::default()
        },
        setting,
    )
    .map_err(|_| ())
}

fn entity_setting(
    config: &Map<String, Value>,
    nested: &str,
    options: &crate::SsoOptions,
) -> EntitySetting {
    let source = config.get(nested).and_then(Value::as_object);
    let mut setting = EntitySetting::default();
    setting.clock_drifts = (
        -options.saml_clock_skew_ms,
        options.saml_clock_skew_ms,
    );
    setting.xml_limits.max_bytes = options.saml_max_response_size;
    setting.is_assertion_encrypted = boolean(source, "isAssertionEncrypted");
    setting.enc_private_key = string(source, "encPrivateKey").map(str::to_owned);
    setting.enc_private_key_pass = string(source, "encPrivateKeyPass").map(str::to_owned);
    setting
}

fn nested_string<'a>(
    config: &'a Map<String, Value>,
    object: &str,
    field: &str,
) -> Option<&'a str> {
    string(config.get(object).and_then(Value::as_object), field)
}

fn string<'a>(source: Option<&'a Map<String, Value>>, field: &str) -> Option<&'a str> {
    source?.get(field).and_then(Value::as_str)
}

fn boolean(source: Option<&Map<String, Value>>, field: &str) -> bool {
    source
        .and_then(|source| source.get(field))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn certificates(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) if !value.is_empty() => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}
