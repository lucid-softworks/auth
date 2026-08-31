use super::*;
use crate::VerificationValue;
use chrono::{Duration, Utc};
use rand::distr::{Alphanumeric, SampleString as _};
use std::collections::HashSet;

const DNS_LABEL_MAX_LENGTH: usize = 63;

pub(in crate::infra::dash::axum::organization) async fn request_verification_token(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(body): Json<ProviderBody>,
) -> Response {
    let sso = match authorized_sso(&service, &dash, &headers, &organization_id, true).await {
        Ok(sso) => sso,
        Err(response) => return *response,
    };
    let provider = match organization_provider(sso, &organization_id, &body.provider_id).await {
        Ok(provider) => provider,
        Err(response) => return *response,
    };
    if provider.domain_verified == Some(true) {
        return error(
            StatusCode::CONFLICT,
            "DOMAIN_VERIFIED",
            "Domain has already been verified",
        );
    }
    let identifier = verification_identifier(&provider.provider_id);
    let token = match service.find_verification_value(&identifier).await {
        Ok(Some(active)) if active.expires_at > Utc::now() => Ok(active.value),
        Ok(_) => fresh_token(&service, &identifier).await,
        Err(storage) => Err(storage),
    };
    let token = match token {
        Ok(token) => token,
        Err(storage) => return route_error(storage),
    };
    Json(json!({
        "success": true,
        "providerId": provider.provider_id,
        "domain": provider.domain,
        "verificationToken": token,
        "txtRecordName": identifier,
    }))
    .into_response()
}

pub(in crate::infra::dash::axum::organization) async fn verify(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(dash): Extension<Arc<DashPlugin>>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(body): Json<ProviderBody>,
) -> Response {
    let sso = match authorized_sso(&service, &dash, &headers, &organization_id, true).await {
        Ok(sso) => sso,
        Err(response) => return *response,
    };
    let provider = match organization_provider(sso, &organization_id, &body.provider_id).await {
        Ok(provider) => provider,
        Err(response) => return *response,
    };
    if provider.domain_verified == Some(true) {
        return already_verified();
    }
    let identifier = verification_identifier(&provider.provider_id);
    if identifier.chars().count() > DNS_LABEL_MAX_LENGTH {
        return error(
            StatusCode::BAD_REQUEST,
            "IDENTIFIER_TOO_LONG",
            "Verification identifier exceeds the DNS label limit of 63 characters",
        );
    }
    let active = match service.find_verification_value(&identifier).await {
        Ok(Some(active)) if active.expires_at > Utc::now() => active,
        Ok(_) => return no_pending_verification(),
        Err(storage) => return route_error(storage),
    };
    let Some(domains) = provider_domains(&provider.domain) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_DOMAIN", "Invalid domain");
    };
    let expected = format!("{}={}", active.identifier, active.value);
    for domain in domains {
        if !has_txt_record(sso, &identifier, &domain, &active.value, &expected).await {
            return missing_record();
        }
    }
    match sso
        .store()
        .verify_domain(&provider.id, &provider.domain)
        .await
    {
        Ok(true) => verified(),
        Ok(false) => provider_changed(),
        Err(storage) => route_error(crate::AuthError::SsoStore(storage)),
    }
}

async fn fresh_token(service: &AuthService, identifier: &str) -> Result<String, crate::AuthError> {
    service.delete_verification_value(identifier).await?;
    let token = Alphanumeric.sample_string(&mut rand::rng(), 24);
    service
        .create_verification_value(VerificationValue::new(
            identifier,
            token.clone(),
            Utc::now() + Duration::days(7),
        ))
        .await?;
    Ok(token)
}

async fn has_txt_record(
    sso: &SsoPlugin,
    identifier: &str,
    domain: &str,
    token: &str,
    expected: &str,
) -> bool {
    sso.dns_resolver()
        .txt_records(&format!("{identifier}.{domain}"))
        .await
        .unwrap_or_default()
        .iter()
        .any(|record| matches!(record.trim(), value if value == token || value == expected))
}

fn verification_identifier(provider_id: &str) -> String {
    format!("_better-auth-token-{provider_id}")
}

fn provider_domains(value: &str) -> Option<Vec<String>> {
    let mut seen = HashSet::new();
    let mut domains = Vec::new();
    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let parsed = url::Url::parse(entry)
            .or_else(|_| url::Url::parse(&format!("https://{entry}")))
            .ok()?;
        let domain = parsed.host_str()?.to_ascii_lowercase();
        if seen.insert(domain.clone()) {
            domains.push(domain);
        }
    }
    (!domains.is_empty()).then_some(domains)
}

fn already_verified() -> Response {
    Json(json!({
        "verified": true,
        "message": "Domain has already been verified",
    }))
    .into_response()
}

fn no_pending_verification() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "NO_PENDING_VERIFICATION",
        "No pending domain verification exists",
    )
}

fn missing_record() -> Response {
    Json(json!({
        "verified": false,
        "message": "Unable to verify domain ownership. The TXT record was not found. It may take up to 48 hours for DNS changes to propagate.",
    }))
    .into_response()
}

fn verified() -> Response {
    Json(json!({
        "verified": true,
        "message": "Domain ownership verified successfully",
    }))
    .into_response()
}

fn provider_changed() -> Response {
    Json(json!({
        "verified": false,
        "message": "SSO provider changed while domain verification was in progress. Reload the provider and try again.",
    }))
    .into_response()
}
