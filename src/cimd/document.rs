use super::{
    CimdFetchRequest, CimdFetchResponse, CimdMetadata, CimdMetadataValidationOptions,
    CimdMetadataValidationResult, CimdOptions,
    cache::{CacheEntry, CacheHeaders},
    discovery::ResolutionFailure,
    validate_cimd_metadata, validate_client_id_url,
};
use crate::OAuthCallbackContext;
use regex::Regex;
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_METADATA_BYTES: usize = 5 * 1_024;

pub(super) enum FetchedDocument {
    Modified {
        metadata: CimdMetadata,
        headers: CacheHeaders,
    },
    NotModified(CacheHeaders),
}

pub(super) async fn fetch_document(
    options: &CimdOptions,
    client_id: &str,
    context: &OAuthCallbackContext,
    cached: Option<&CacheEntry>,
) -> Result<FetchedDocument, ResolutionFailure> {
    if let Some(error) = validate_client_id_url(client_id) {
        return Err(ResolutionFailure::Invalid(error));
    }
    if let Some(policy) = &options.metadata_document_url_policy
        && !policy.allowed(client_id, context).await
    {
        return Err(ResolutionFailure::Invalid(
            "client_id URL is not permitted by the server's fetch policy".into(),
        ));
    }
    let mut headers = BTreeMap::from([("accept".into(), "application/json".into())]);
    if let Some(etag) = cached.and_then(|entry| entry.headers.etag.as_ref()) {
        headers.insert("if-none-match".into(), etag.clone());
    }
    if let Some(modified) = cached.and_then(|entry| entry.headers.last_modified.as_ref()) {
        headers.insert("if-modified-since".into(), modified.clone());
    }
    let response = tokio::time::timeout(
        FETCH_TIMEOUT,
        options
            .fetch_client_metadata_resource
            .fetch(CimdFetchRequest {
                url: client_id.into(),
                method: "GET".into(),
                headers,
                timeout: FETCH_TIMEOUT,
                maximum_response_bytes: MAX_METADATA_BYTES,
            }),
    )
    .await
    .map_err(|_| {
        ResolutionFailure::Invalid("Metadata document fetch timed out after 5000ms".into())
    })?
    .map_err(|_| {
        ResolutionFailure::Invalid(
            "Failed to fetch metadata document (network error or redirect blocked)".into(),
        )
    })?;
    let conditional = cached.is_some_and(|entry| {
        entry.headers.etag.is_some() || entry.headers.last_modified.is_some()
    });
    validate_response(options, client_id, response, conditional)
}

fn validate_response(
    options: &CimdOptions,
    client_id: &str,
    response: CimdFetchResponse,
    conditional: bool,
) -> Result<FetchedDocument, ResolutionFailure> {
    if response.redirected {
        return Err(ResolutionFailure::Invalid(
            "Metadata document fetch must not follow redirects".into(),
        ));
    }
    let headers = CacheHeaders::from_headers(&response.headers);
    if response.status == 304 {
        return conditional
            .then_some(FetchedDocument::NotModified(headers))
            .ok_or_else(|| {
                ResolutionFailure::Invalid(
                    "Metadata document returned 304 without a conditional validator".into(),
                )
            });
    }
    if response.status != 200 {
        return Err(ResolutionFailure::Invalid(format!(
            "Metadata document fetch returned HTTP {}",
            response.status
        )));
    }
    validate_body(options, client_id, response, headers)
}

fn validate_body(
    options: &CimdOptions,
    client_id: &str,
    response: CimdFetchResponse,
    headers: CacheHeaders,
) -> Result<FetchedDocument, ResolutionFailure> {
    static JSON_MEDIA_TYPE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let json_media_type = JSON_MEDIA_TYPE.get_or_init(|| {
        Regex::new(r"(?i)^application/(?:[-\w.]+\+)?json\s*(?:;|$)")
            .expect("static JSON media type expression")
    });
    let content_type = response.content_type().unwrap_or_default();
    if !json_media_type.is_match(content_type) {
        return Err(ResolutionFailure::Invalid(format!(
            "Metadata document must be JSON (got Content-Type \"{}\")",
            if content_type.is_empty() {
                "(none)"
            } else {
                content_type
            }
        )));
    }
    if response.body.len() > MAX_METADATA_BYTES
        || response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value)
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAX_METADATA_BYTES)
    {
        return Err(ResolutionFailure::Invalid(
            "Metadata document exceeds 5KB size limit".into(),
        ));
    }
    let raw: Value = serde_json::from_slice(&response.body)
        .map_err(|_| ResolutionFailure::Invalid("Metadata document is not valid JSON".into()))?;
    match validate_cimd_metadata(
        client_id,
        &raw,
        &CimdMetadataValidationOptions {
            origin_bound_fields: options.origin_bound_fields.clone(),
            metadata_profile: options.metadata_profile,
        },
    ) {
        CimdMetadataValidationResult::Valid { metadata, warnings } => {
            for warning in warnings {
                tracing::warn!(%warning, "cimd metadata document warning");
            }
            Ok(FetchedDocument::Modified { metadata, headers })
        }
        CimdMetadataValidationResult::Invalid { error, .. } => {
            Err(ResolutionFailure::Invalid(error))
        }
    }
}
