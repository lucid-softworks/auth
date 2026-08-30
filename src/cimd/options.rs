use super::{CimdMetadata, CimdMetadataProfile, CimdMetadataResourceFetcher, duration::parse_duration};
use crate::{OAuthCallbackContext, OAuthProviderClient};
use async_trait::async_trait;
use std::{fmt, sync::Arc, time::Duration};

#[derive(Debug, Clone, PartialEq)]
pub enum CimdDuration {
    Seconds(f64),
    Text(String),
}

impl From<f64> for CimdDuration {
    fn from(value: f64) -> Self { Self::Seconds(value) }
}

impl From<u64> for CimdDuration {
    fn from(value: u64) -> Self { Self::Seconds(value as f64) }
}

impl From<&str> for CimdDuration {
    fn from(value: &str) -> Self { Self::Text(value.into()) }
}

impl From<String> for CimdDuration {
    fn from(value: String) -> Self { Self::Text(value) }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CimdMetadataFetchPolicy {
    pub minimum_fetch_interval: CimdDuration,
    pub maximum_concurrent_fetches: usize,
    pub maximum_concurrent_fetches_per_origin: usize,
    pub maximum_fetches_per_minute: usize,
    pub maximum_fetches_per_origin_per_minute: usize,
}

impl Default for CimdMetadataFetchPolicy {
    fn default() -> Self {
        Self {
            minimum_fetch_interval: CimdDuration::Seconds(1.0),
            maximum_concurrent_fetches: 16,
            maximum_concurrent_fetches_per_origin: 4,
            maximum_fetches_per_minute: 120,
            maximum_fetches_per_origin_per_minute: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CimdConfigError {
    #[error("cimd {0} must be a non-negative number of seconds or duration string")]
    InvalidDuration(&'static str),
    #[error("cimd metadataFetchPolicy.{0} must be a positive integer")]
    InvalidFetchLimit(&'static str),
    #[error("cimd maxCacheEntries must be a positive integer")]
    InvalidCacheEntries,
}

#[async_trait]
pub trait CimdMetadataDocumentUrlPolicy: Send + Sync {
    async fn allowed(&self, client_id_url: &str, context: &OAuthCallbackContext) -> bool;
}

#[derive(Debug, Clone)]
pub struct CimdClientCreatedEvent {
    pub client: OAuthProviderClient,
    pub client_metadata_document: CimdMetadata,
    pub context: OAuthCallbackContext,
}

#[derive(Debug, Clone)]
pub struct CimdClientRefreshedEvent {
    pub client: OAuthProviderClient,
    pub previous_client: OAuthProviderClient,
    pub client_metadata_document: CimdMetadata,
    pub context: OAuthCallbackContext,
}

#[async_trait]
pub trait CimdClientLifecycle: Send + Sync {
    async fn created(&self, _event: CimdClientCreatedEvent) -> Result<(), crate::AuthError> {
        Ok(())
    }

    async fn refreshed(&self, _event: CimdClientRefreshedEvent) -> Result<(), crate::AuthError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct CimdOptions {
    pub fetch_client_metadata_resource: Arc<dyn CimdMetadataResourceFetcher>,
    pub metadata_profile: Option<CimdMetadataProfile>,
    pub metadata_revalidation_interval: CimdDuration,
    pub metadata_fetch_policy: CimdMetadataFetchPolicy,
    pub max_cache_entries: usize,
    pub origin_bound_fields: Vec<String>,
    pub metadata_document_url_policy: Option<Arc<dyn CimdMetadataDocumentUrlPolicy>>,
    pub lifecycle: Option<Arc<dyn CimdClientLifecycle>>,
}

impl CimdOptions {
    pub fn new(fetcher: Arc<dyn CimdMetadataResourceFetcher>) -> Self {
        Self {
            fetch_client_metadata_resource: fetcher,
            metadata_profile: None,
            metadata_revalidation_interval: CimdDuration::Text("60m".into()),
            metadata_fetch_policy: CimdMetadataFetchPolicy::default(),
            max_cache_entries: 1_000,
            origin_bound_fields: vec!["post_logout_redirect_uris".into(), "client_uri".into()],
            metadata_document_url_policy: None,
            lifecycle: None,
        }
    }

    pub fn validate(&self) -> Result<(), CimdConfigError> {
        parse_duration(&self.metadata_revalidation_interval, "metadataRevalidationInterval")?;
        parse_duration(
            &self.metadata_fetch_policy.minimum_fetch_interval,
            "metadataFetchPolicy.minimumFetchInterval",
        )?;
        if self.max_cache_entries == 0 { return Err(CimdConfigError::InvalidCacheEntries); }
        for (name, value) in [
            ("maximumConcurrentFetches", self.metadata_fetch_policy.maximum_concurrent_fetches),
            ("maximumConcurrentFetchesPerOrigin", self.metadata_fetch_policy.maximum_concurrent_fetches_per_origin),
            ("maximumFetchesPerMinute", self.metadata_fetch_policy.maximum_fetches_per_minute),
            ("maximumFetchesPerOriginPerMinute", self.metadata_fetch_policy.maximum_fetches_per_origin_per_minute),
        ] {
            if value == 0 { return Err(CimdConfigError::InvalidFetchLimit(name)); }
        }
        Ok(())
    }

    pub(crate) fn revalidation_interval(&self) -> Duration {
        parse_duration(&self.metadata_revalidation_interval, "metadataRevalidationInterval")
            .expect("validated CIMD revalidation interval")
    }

    pub(crate) fn minimum_fetch_interval(&self) -> Duration {
        parse_duration(
            &self.metadata_fetch_policy.minimum_fetch_interval,
            "metadataFetchPolicy.minimumFetchInterval",
        )
        .expect("validated CIMD fetch interval")
    }
}

impl fmt::Debug for CimdOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CimdOptions")
            .field("metadata_profile", &self.metadata_profile)
            .field("metadata_revalidation_interval", &self.metadata_revalidation_interval)
            .field("metadata_fetch_policy", &self.metadata_fetch_policy)
            .field("max_cache_entries", &self.max_cache_entries)
            .field("origin_bound_fields", &self.origin_bound_fields)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CimdFetchError, CimdFetchRequest, CimdFetchResponse};

    struct Fetcher;

    #[async_trait]
    impl CimdMetadataResourceFetcher for Fetcher {
        async fn fetch(&self, _request: CimdFetchRequest) -> Result<CimdFetchResponse, CimdFetchError> {
            unreachable!()
        }
    }

    #[test]
    fn defaults_and_construction_errors_match_upstream() {
        let mut options = CimdOptions::new(Arc::new(Fetcher));
        assert_eq!(options.max_cache_entries, 1_000);
        assert_eq!(options.revalidation_interval(), Duration::from_secs(3_600));
        assert!(options.validate().is_ok());
        options.metadata_fetch_policy.maximum_concurrent_fetches = 0;
        assert_eq!(
            options.validate(),
            Err(CimdConfigError::InvalidFetchLimit("maximumConcurrentFetches"))
        );

        let mut options = CimdOptions::new(Arc::new(Fetcher));
        options.metadata_fetch_policy.minimum_fetch_interval =
            CimdDuration::Seconds(f64::MAX);
        assert_eq!(
            options.validate().unwrap_err().to_string(),
            "cimd metadataFetchPolicy.minimumFetchInterval must be a non-negative number of seconds or duration string"
        );
    }
}
