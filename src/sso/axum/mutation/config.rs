use super::UpdateBody;
use crate::{
    AuthService, SsoPlugin, SsoProvider, SsoProviderUpdate,
    sso::validate_oidc_endpoint_url,
};
use axum::{http::StatusCode, response::Response};
use serde_json::{Map, Value, json};

const OIDC_FIELDS: [&str; 14] = [
    "clientId",
    "clientSecret",
    "authorizationEndpoint",
    "tokenEndpoint",
    "userInfoEndpoint",
    "tokenEndpointAuthentication",
    "privateKeyId",
    "privateKeyAlgorithm",
    "jwksEndpoint",
    "discoveryEndpoint",
    "scopes",
    "pkce",
    "overrideUserInfo",
    "mapping",
];
const OIDC_IDENTITY_FIELDS: [&str; 6] = [
    "authorizationEndpoint",
    "clientId",
    "discoveryEndpoint",
    "jwksEndpoint",
    "tokenEndpoint",
    "userInfoEndpoint",
];
const SAML_FIELDS: [&str; 13] = [
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
    "mapping",
];

pub(super) struct Prepared {
    pub(super) update: SsoProviderUpdate,
    pub(super) identity_boundary_changed: bool,
}

pub(super) fn prepare(
    service: &AuthService,
    plugin: &SsoPlugin,
    provider: &SsoProvider,
    body: &UpdateBody,
) -> Result<Prepared, Box<Response>> {
    if body.issuer.is_none()
        && body.domain.is_none()
        && body.oidc_config.is_none()
        && body.saml_config.is_none()
    {
        return Err(Box::new(error("No fields provided for update")));
    }
    if body
        .issuer
        .as_deref()
        .is_some_and(|issuer| url::Url::parse(issuer).is_err())
    {
        return Err(Box::new(super::super::support::error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid issuer",
        )));
    }
    let issuer = body.issuer.as_deref().unwrap_or(&provider.issuer);
    let (oidc_config, oidc_changed) = match body.oidc_config.as_ref() {
        Some(changes) => {
            let current = provider.oidc_config.as_ref().and_then(Value::as_object).ok_or_else(|| {
                Box::new(error(
                    "Cannot update OIDC config for a provider that doesn't have OIDC configured",
                ))
            })?;
            let merged = merge_oidc(
                service,
                issuer,
                current,
                changes,
                plugin.has_private_key_source(&provider.provider_id),
            )?;
            let changed = changed(current, &merged, &OIDC_IDENTITY_FIELDS);
            (Some(Some(Value::Object(merged))), changed)
        }
        None => (None, false),
    };
    let (saml_config, saml_changed) = match body.saml_config.as_ref() {
        Some(changes) => {
            let current = provider.saml_config.as_ref().and_then(Value::as_object).ok_or_else(|| {
                Box::new(error(
                    "Cannot update SAML config for a provider that doesn't have SAML configured",
                ))
            })?;
            let merged = merge_saml(issuer, current, changes, plugin.options())?;
            let changed = changed(current, &merged, &["audience", "callbackUrl"]);
            (Some(Some(Value::Object(merged))), changed)
        }
        None => (None, false),
    };
    let issuer_changed = body
        .issuer
        .as_deref()
        .is_some_and(|issuer| issuer != provider.issuer);
    let domain_changed = body
        .domain
        .as_deref()
        .is_some_and(|domain| domain != provider.domain);
    Ok(Prepared {
        update: SsoProviderUpdate {
            issuer: body.issuer.clone(),
            oidc_config,
            saml_config,
            domain: body.domain.clone(),
            domain_verified: (domain_changed && provider.domain_verified.is_some()).then_some(false),
            ..SsoProviderUpdate::default()
        },
        identity_boundary_changed: issuer_changed || oidc_changed || saml_changed,
    })
}

fn merge_oidc(
    service: &AuthService,
    issuer: &str,
    current: &Map<String, Value>,
    changes: &Map<String, Value>,
    has_private_key_source: bool,
) -> Result<Map<String, Value>, Box<Response>> {
    for field in [
        "authorizationEndpoint",
        "tokenEndpoint",
        "userInfoEndpoint",
        "jwksEndpoint",
        "discoveryEndpoint",
    ] {
        if let Some(endpoint) = changes.get(field).and_then(Value::as_str) {
            validate_oidc_endpoint_url(field, endpoint, |url| service.trusts_origin(url))
                .map_err(|error| {
                    Box::new(crate::axum::api_error(
                        StatusCode::BAD_REQUEST,
                        error.code.as_str(),
                        error.message,
                    ))
                })?;
        }
    }
    let mut merged = current.clone();
    copy_known(&mut merged, changes, &OIDC_FIELDS);
    merged.insert("issuer".into(), json!(issuer));
    merged
        .entry("pkce")
        .or_insert_with(|| Value::Bool(true));
    let private_key = merged
        .get("tokenEndpointAuthentication")
        .and_then(Value::as_str)
        == Some("private_key_jwt");
    if private_key && !has_private_key_source {
        return Err(Box::new(error(
            "private_key_jwt authentication requires either a resolvePrivateKey callback or a privateKey in defaultSSO",
        )));
    }
    if !private_key
        && merged
        .get("clientSecret")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Box::new(error(
            "clientSecret is required when using client_secret_basic or client_secret_post authentication",
        )));
    }
    Ok(merged)
}

fn merge_saml(
    issuer: &str,
    current: &Map<String, Value>,
    changes: &Map<String, Value>,
    options: &crate::SsoOptions,
) -> Result<Map<String, Value>, Box<Response>> {
    let mut merged = current.clone();
    copy_known(&mut merged, changes, &SAML_FIELDS);
    if changes.get("idpInitiatedCallbackUrl") == Some(&Value::Null) {
        merged.remove("idpInitiatedCallbackUrl");
    }
    merged.insert("issuer".into(), json!(issuer));
    crate::sso::validate_configuration_algorithms(
        &merged,
        &options.saml_algorithms,
    )
    .map_err(|error| {
        Box::new(super::super::support::error(
            StatusCode::BAD_REQUEST,
            error.code,
            error.message,
        ))
    })?;
    Ok(merged)
}

fn copy_known(target: &mut Map<String, Value>, changes: &Map<String, Value>, fields: &[&str]) {
    for field in fields {
        if let Some(value) = changes.get(*field) {
            target.insert((*field).into(), value.clone());
        }
    }
}

fn changed(current: &Map<String, Value>, updated: &Map<String, Value>, fields: &[&str]) -> bool {
    fields
        .iter()
        .any(|field| current.get(*field) != updated.get(*field))
}

fn error(message: &'static str) -> Response {
    super::super::support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
}
