use super::support;
use crate::{AuthService, SsoPlugin, SsoStoreError, VerificationValue};
use axum::{
    Extension, Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use rand::distr::{Alphanumeric, SampleString as _};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashSet, sync::Arc};

const DNS_LABEL_MAX_LENGTH: usize = 63;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DomainBody {
    provider_id: String,
}

pub(super) async fn request(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<DomainBody>,
) -> Response {
    let (_, provider) =
        match support::authorized_provider(&service, &plugin, &headers, &body.provider_id).await {
            Ok(provider) => provider,
            Err(response) => return *response,
        };
    if provider.domain_verified == Some(true) {
        return already_verified();
    }
    let identifier = identifier(&provider.provider_id);
    let active = match service.find_verification_value(&identifier).await {
        Ok(active) => active,
        Err(error) => return storage(error),
    };
    if let Some(active) = active.filter(|active| active.expires_at > Utc::now()) {
        return (
            StatusCode::CREATED,
            Json(json!({"domainVerificationToken": active.value})),
        )
            .into_response();
    }
    if let Err(error) = service.delete_verification_value(&identifier).await {
        return storage(error);
    }
    let token = Alphanumeric.sample_string(&mut rand::rng(), 24);
    if let Err(error) = service
        .create_verification_value(VerificationValue::new(
            identifier,
            token.clone(),
            Utc::now() + Duration::days(7),
        ))
        .await
    {
        return storage(error);
    }
    (
        StatusCode::CREATED,
        Json(json!({"domainVerificationToken": token})),
    )
        .into_response()
}

pub(super) async fn verify(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<Arc<SsoPlugin>>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<DomainBody>,
) -> Response {
    let (_, provider) =
        match support::authorized_provider(&service, &plugin, &headers, &body.provider_id).await {
            Ok(provider) => provider,
            Err(response) => return *response,
        };
    if provider.domain_verified == Some(true) {
        return already_verified();
    }
    let identifier = identifier(&provider.provider_id);
    if identifier.chars().count() > DNS_LABEL_MAX_LENGTH {
        return support::error(
            StatusCode::BAD_REQUEST,
            "IDENTIFIER_TOO_LONG",
            format!(
                "Verification identifier exceeds the DNS label limit of {DNS_LABEL_MAX_LENGTH} characters"
            ),
        );
    }
    let active = match service.find_verification_value(&identifier).await {
        Ok(Some(active)) if active.expires_at > Utc::now() => active,
        Ok(_) => {
            return support::error(
                StatusCode::NOT_FOUND,
                "NO_PENDING_VERIFICATION",
                "No pending domain verification exists",
            );
        }
        Err(error) => return storage(error),
    };
    let domains = match provider_domains(&provider.domain) {
        Some(domains) => domains,
        None => return support::error(StatusCode::BAD_REQUEST, "INVALID_DOMAIN", "Invalid domain"),
    };
    let expected = format!("{}={}", active.identifier, active.value);
    for domain in domains {
        let records = plugin
            .dns_resolver()
            .txt_records(&format!("{identifier}.{domain}"))
            .await
            .unwrap_or_default();
        if !records.iter().any(|record| {
            let record = record.trim();
            record == active.value || record == expected
        }) {
            return support::error(
                StatusCode::BAD_GATEWAY,
                "DOMAIN_VERIFICATION_FAILED",
                format!("Unable to verify domain ownership for {domain}. Try again later"),
            );
        }
    }
    match plugin
        .store()
        .verify_domain(&provider.id, &provider.domain)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => support::error(
            StatusCode::CONFLICT,
            "SSO_PROVIDER_CHANGED",
            "SSO provider changed while domain verification was in progress. Reload the provider and try again",
        ),
        Err(error) => support::storage(error),
    }
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

fn identifier(provider_id: &str) -> String {
    format!("_better-auth-token-{provider_id}")
}

fn already_verified() -> Response {
    support::error(
        StatusCode::CONFLICT,
        "DOMAIN_VERIFIED",
        "Domain has already been verified",
    )
}

fn storage(error: crate::AuthError) -> Response {
    support::storage(SsoStoreError::Storage(error.to_string()))
}
