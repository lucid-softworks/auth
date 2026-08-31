use super::{forbidden, has_access, organization_provider, sso_feature_error};
use crate::{
    AuthService, DashPlugin, NewSsoProvider, SsoPlugin, SsoProviderUpdate, SsoStoreError,
    VerificationValue,
};
use axum::{
    Extension, Json,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use rand::distr::{Alphanumeric, SampleString as _};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateBody {
    provider_id: String,
    domain: String,
    protocol: Protocol,
    user_id: String,
    saml_config: Option<Map<String, Value>>,
    oidc_config: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateBody {
    provider_id: String,
    domain: String,
    protocol: Protocol,
    saml_config: Option<Map<String, Value>>,
    oidc_config: Option<Map<String, Value>>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum Protocol {
    #[serde(rename = "SAML")]
    Saml,
    #[serde(rename = "OIDC")]
    Oidc,
}

pub(crate) async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(body): Json<CreateBody>,
) -> Response {
    let sso = match authorized(&service, &dash, &headers, &organization_id).await {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    if body.provider_id.is_empty() || body.domain.is_empty() || body.user_id.is_empty() {
        return bad_request("Provider ID, domain, and user ID are required");
    }
    if service.dash_event_user(&body.user_id).await.ok().flatten().is_none() {
        return bad_request("SSO provider user not found");
    }
    let (issuer, oidc_config, saml_config) = match configuration(
        &service,
        &body.provider_id,
        body.protocol,
        body.oidc_config,
        body.saml_config,
        None,
    ) {
        Ok(config) => config,
        Err(response) => return response,
    };
    let id = match service.generate_plugin_database_id("ssoProvider") {
        Ok(id) => id,
        Err(error) => return super::super::support::route_error(error),
    };
    let provider = match sso
        .store()
        .create(NewSsoProvider {
            id,
            issuer,
            oidc_config,
            saml_config,
            user_id: body.user_id,
            provider_id: body.provider_id.clone(),
            organization_id: Some(organization_id),
            domain: body.domain.clone(),
            domain_verified: sso.options().domain_verification.then_some(false),
            additional_fields: Map::new(),
        })
        .await
    {
        Ok(provider) => provider,
        Err(error) => return storage(error),
    };
    let verification_token = if sso.options().domain_verification {
        match save_verification(&service, &provider.provider_id).await {
            Ok(token) => Some(token),
            Err(error) => return super::super::support::route_error(error),
        }
    } else {
        None
    };
    Json(json!({
        "success": true,
        "provider": {
            "id": provider.provider_id,
            "providerId": provider.provider_id,
            "domain": provider.domain,
        },
        "domainVerification": {
            "txtRecordName": format!("_better-auth-token-{}", provider.provider_id),
            "verificationToken": verification_token,
        }
    }))
    .into_response()
}

pub(crate) async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(body): Json<UpdateBody>,
) -> Response {
    let sso = match authorized(&service, &dash, &headers, &organization_id).await {
        Ok(plugin) => plugin,
        Err(response) => return response,
    };
    let existing = match organization_provider(sso, &organization_id, &body.provider_id).await {
        Ok(provider) => provider,
        Err(response) => return *response,
    };
    let (issuer, oidc_config, saml_config) = match configuration(
        &service,
        &body.provider_id,
        body.protocol,
        body.oidc_config,
        body.saml_config,
        existing.oidc_config.as_ref(),
    ) {
        Ok(config) => config,
        Err(response) => return response,
    };
    let identity_changed = issuer != existing.issuer
        || oidc_config != existing.oidc_config
        || saml_config != existing.saml_config;
    let provider = crate::sso::update_provider_guarded(
        &service,
        sso,
        &existing,
        SsoProviderUpdate {
            issuer: Some(issuer),
            oidc_config: Some(oidc_config),
            saml_config: Some(saml_config),
            domain: (body.domain != existing.domain).then_some(body.domain.clone()),
            domain_verified: (body.domain != existing.domain
                && existing.domain_verified.is_some())
            .then_some(false),
            ..SsoProviderUpdate::default()
        },
        identity_changed,
    )
    .await;
    match provider {
        Ok(provider) => Json(json!({
            "success": true,
            "provider": {
                "id": existing.id,
                "providerId": provider.provider_id,
                "domain": provider.domain,
            }
        }))
        .into_response(),
        Err(crate::AuthError::SsoProviderMutationRejected) => super::super::support::error(
            StatusCode::CONFLICT,
            "SSO_PROVIDER_MUTATION_REJECTED",
            "SSO provider mutation is not allowed",
        ),
        Err(error) => super::super::support::route_error(error),
    }
}

type ProviderConfiguration = (String, Option<Value>, Option<Value>);

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
fn configuration(
    service: &AuthService,
    provider_id: &str,
    protocol: Protocol,
    oidc: Option<Map<String, Value>>,
    saml: Option<Map<String, Value>>,
    existing_oidc: Option<&Value>,
) -> Result<ProviderConfiguration, Response> {
    match protocol {
        Protocol::Oidc => oidc_configuration(oidc, existing_oidc),
        Protocol::Saml => saml_configuration(service, provider_id, saml),
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
fn oidc_configuration(
    oidc: Option<Map<String, Value>>,
    existing: Option<&Value>,
) -> Result<ProviderConfiguration, Response> {
    let mut oidc = oidc.ok_or_else(|| bad_request("OIDC configuration is required"))?;
    for field in ["issuer", "authorizationEndpoint", "tokenEndpoint", "jwksEndpoint"] {
        if oidc.get(field).and_then(Value::as_str).is_none_or(str::is_empty) {
            return Err(bad_request("OIDC discovery must be resolved before submitting; provide issuer, authorizationEndpoint, tokenEndpoint, and jwksEndpoint"));
        }
    }
    if oidc.get("clientSecret").and_then(Value::as_str).is_none_or(str::is_empty) {
        let secret = existing
            .and_then(Value::as_object)
            .and_then(|config| config.get("clientSecret"))
            .cloned()
            .ok_or_else(|| bad_request("Client secret is required when creating or updating an OIDC provider"))?;
        oidc.insert("clientSecret".into(), secret);
    }
    let issuer = oidc["issuer"].as_str().expect("issuer checked").to_owned();
    let discovery = oidc
        .get("discoveryEndpoint")
        .or_else(|| oidc.get("discoveryUrl"))
        .cloned()
        .unwrap_or_else(|| json!(issuer));
    oidc.remove("discoveryUrl");
    oidc.insert("discoveryEndpoint".into(), discovery);
    oidc.insert("pkce".into(), Value::Bool(true));
    Ok((issuer, Some(Value::Object(oidc)), None))
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
fn saml_configuration(
    service: &AuthService,
    provider_id: &str,
    saml: Option<Map<String, Value>>,
) -> Result<ProviderConfiguration, Response> {
    let saml = saml.ok_or_else(|| bad_request("SAML configuration is required"))?;
    let metadata = saml
        .get("idpMetadata")
        .and_then(Value::as_object)
        .and_then(|value| value.get("metadata"))
        .and_then(Value::as_str);
    if metadata.is_none()
        && saml
            .get("idpMetadata")
            .and_then(Value::as_object)
            .and_then(|value| value.get("metadataUrl"))
            .is_some()
    {
        return Err(bad_request("IdP metadata URL must be resolved before submitting; provide idpMetadata.metadata"));
    }
    if metadata.is_some_and(|value| value.len() > crate::sso::DEFAULT_MAX_SAML_METADATA_SIZE) {
        return Err(bad_request("IdP metadata exceeds maximum allowed size"));
    }
    let entry_point = saml
        .get("entryPoint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| metadata.and_then(metadata_entry_point));
    let Some(entry_point) = entry_point else {
        return Err(bad_request("SAML entry point URL is required; provide entryPoint or IdP metadata with SingleSignOnService Location"));
    };
    let base = service
        .auth_base_url()
        .map(|url| url.to_string().trim_end_matches('/').to_owned())
        .unwrap_or_else(|| service.base_path().trim_end_matches('/').to_owned());
    let sp_issuer = format!("{base}/sso/saml2/sp/metadata?providerId={provider_id}");
    let entity_id = saml.get("entityId").and_then(Value::as_str).filter(|value| !value.trim().is_empty());
    if metadata.is_none() && entity_id.is_none() {
        return Err(bad_request("IdP entity ID is required when IdP metadata XML is not provided"));
    }
    let issuer = entity_id.unwrap_or(&sp_issuer).to_owned();
    let mut config = Map::new();
    config.insert("issuer".into(), json!(issuer));
    config.insert("entryPoint".into(), json!(entry_point));
    config.insert(
        "idpMetadata".into(),
        metadata.map_or_else(
            || json!({"entityID": entity_id}),
            |metadata| json!({"metadata": metadata}),
        ),
    );
    config.insert(
        "wantAssertionsSigned".into(),
        saml.get("wantAssertionsSigned").cloned().unwrap_or(Value::Bool(true)),
    );
    for field in ["cert", "mapping"] {
        if let Some(value) = saml.get(field) {
            config.insert(field.into(), value.clone());
        }
    }
    Ok((issuer, None, Some(Value::Object(config))))
}

#[allow(
    clippy::result_large_err,
    reason = "the error is an exact Axum response returned directly by the route"
)]
async fn authorized<'a>(
    service: &'a AuthService,
    dash: &DashPlugin,
    headers: &HeaderMap,
    organization_id: &str,
) -> Result<&'a SsoPlugin, Response> {
    let claims = super::super::support::claims::<super::super::support::OrganizationClaims>(dash, headers).await?;
    super::super::support::plugin(service)?;
    if !has_access(&claims, organization_id) {
        return Err(forbidden());
    }
    service.sso_plugin().ok_or_else(sso_feature_error)
}

async fn save_verification(service: &AuthService, provider_id: &str) -> Result<String, crate::AuthError> {
    let token = Alphanumeric.sample_string(&mut rand::rng(), 24);
    service
        .create_verification_value(VerificationValue::new(
            format!("_better-auth-token-{provider_id}"),
            token.clone(),
            Utc::now() + Duration::days(7),
        ))
        .await?;
    Ok(token)
}

fn metadata_entry_point(metadata: &str) -> Option<String> {
    let marker = "Location=\"";
    let start = metadata.find("SingleSignOnService")?;
    let value = &metadata[start..];
    let start = value.find(marker)? + marker.len();
    let end = value[start..].find('"')? + start;
    Some(value[start..end].to_owned())
}

fn storage(error: SsoStoreError) -> Response {
    super::super::support::route_error(crate::AuthError::SsoStore(error))
}

fn bad_request(message: &'static str) -> Response {
    super::super::support::error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
}
