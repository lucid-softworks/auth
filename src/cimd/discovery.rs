use super::{
    CimdFetchRequest, CimdMetadata, CimdOptions,
    cache::{CacheEntry, CacheHeaders, cache_entry},
    document::{FetchedDocument, fetch_document},
    governor::FetchGovernor,
    persistence::{ProviderBinding, persist_client},
};
use crate::{
    AuthError, OAuthCallbackContext, OAuthClientMetadataResourceResponse, OAuthProviderClient,
    OAuthProviderError, OAuthProviderExtension, OAuthProviderPluginConfig, OAuthProviderStore,
};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESOURCE_BYTES: usize = 64 * 1_024;

pub struct CimdClientDiscovery {
    options: Arc<CimdOptions>,
    state: Mutex<DiscoveryState>,
    binding: RwLock<Option<ProviderBinding>>,
}

impl std::fmt::Debug for CimdClientDiscovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CimdClientDiscovery")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct DiscoveryState {
    cache: IndexMap<String, CacheEntry>,
    in_flight: HashMap<String, Arc<InFlight>>,
    governor: FetchGovernor,
}

struct InFlight {
    result: Mutex<Option<ResolutionResult>>,
    notify: Notify,
}

type ResolutionResult = Result<Option<OAuthProviderClient>, ResolutionFailure>;

#[derive(Debug, Clone)]
pub(super) enum ResolutionFailure {
    Invalid(String),
    TemporarilyUnavailable(String),
    Server(String),
}

pub fn create_cimd_client_discovery(
    options: CimdOptions,
) -> Result<Arc<CimdClientDiscovery>, super::CimdConfigError> {
    options.validate()?;
    Ok(Arc::new(CimdClientDiscovery {
        options: Arc::new(options),
        state: Mutex::new(DiscoveryState::default()),
        binding: RwLock::new(None),
    }))
}

impl CimdClientDiscovery {
    async fn resolve(
        &self,
        client_id: &str,
        existing: Option<&OAuthProviderClient>,
        context: &OAuthCallbackContext,
    ) -> ResolutionResult {
        if !super::is_cimd_client_id_url_candidate(client_id) {
            return Ok(None);
        }
        let binding = self.binding.read().expect("CIMD binding lock").clone().ok_or_else(|| {
            ResolutionFailure::Server("cimd discovery is not bound to an OAuth Provider".into())
        })?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let plan = self.plan_resolution(client_id, existing, now_ms).await?;
        match plan {
            ResolutionPlan::Existing(client) => Ok(Some(*client)),
            ResolutionPlan::Cached(metadata) => persist_client(
                &binding,
                &self.options,
                client_id,
                &metadata,
                None,
                context,
            )
            .await
            .map(Some)
            .map_err(ResolutionFailure::from),
            ResolutionPlan::Join(in_flight) => wait_for(in_flight).await,
            ResolutionPlan::Fetch {
                in_flight,
                cached,
                origin,
            } => {
                let result = self
                    .fetch_resolve_store(&binding, client_id, existing, context, *cached)
                    .await;
                self.complete(client_id, &origin, in_flight, result.clone())
                    .await;
                result
            }
        }
    }

    async fn plan_resolution(
        &self,
        client_id: &str,
        existing: Option<&OAuthProviderClient>,
        now_ms: i64,
    ) -> Result<ResolutionPlan, ResolutionFailure> {
        let mut state = self.state.lock().await;
        let cached = state.cache.shift_remove(client_id);
        if let Some(entry) = cached.as_ref() {
            state.cache.insert(client_id.into(), entry.clone());
            if entry.expires_at_ms > now_ms {
                return Ok(existing.cloned().map_or_else(
                    || ResolutionPlan::Cached(entry.metadata.clone()),
                    |client| ResolutionPlan::Existing(Box::new(client)),
                ));
            }
        }
        if let Some(in_flight) = state.in_flight.get(client_id) {
            return Ok(ResolutionPlan::Join(in_flight.clone()));
        }
        let origin = state
            .governor
            .acquire(client_id, &self.options, now_ms)
            .map_err(ResolutionFailure::TemporarilyUnavailable)?;
        let in_flight = Arc::new(InFlight {
            result: Mutex::new(None),
            notify: Notify::new(),
        });
        state.in_flight.insert(client_id.into(), in_flight.clone());
        Ok(ResolutionPlan::Fetch {
            in_flight,
            cached: Box::new(cached),
            origin,
        })
    }

    async fn fetch_resolve_store(
        &self,
        binding: &ProviderBinding,
        client_id: &str,
        existing: Option<&OAuthProviderClient>,
        context: &OAuthCallbackContext,
        cached: Option<CacheEntry>,
    ) -> ResolutionResult {
        let fetched = fetch_document(&self.options, client_id, context, cached.as_ref()).await?;
        let (metadata, headers) = match fetched {
            FetchedDocument::Modified { metadata, headers } => (metadata, headers),
            FetchedDocument::NotModified(headers) => {
                let cached = cached.as_ref().ok_or_else(|| {
                    ResolutionFailure::Invalid(
                        "Metadata document returned 304 without a validated cached document".into(),
                    )
                })?;
                (cached.metadata.clone(), cached.headers.merge(&headers))
            }
        };
        let client = persist_client(
            binding,
            &self.options,
            client_id,
            &metadata,
            existing,
            context,
        )
        .await
        .map_err(ResolutionFailure::from)?;
        self.store_cache(client_id, metadata, headers).await;
        Ok(Some(client))
    }

    async fn store_cache(&self, client_id: &str, metadata: CimdMetadata, headers: CacheHeaders) {
        let entry = cache_entry(
            metadata,
            headers,
            self.options.revalidation_interval(),
            chrono::Utc::now().timestamp_millis(),
        );
        let mut state = self.state.lock().await;
        state.cache.shift_remove(client_id);
        if let Some(entry) = entry {
            while state.cache.len() >= self.options.max_cache_entries {
                state.cache.shift_remove_index(0);
            }
            state.cache.insert(client_id.into(), entry);
        }
    }

    async fn complete(
        &self,
        client_id: &str,
        origin: &str,
        in_flight: Arc<InFlight>,
        result: ResolutionResult,
    ) {
        *in_flight.result.lock().await = Some(result);
        in_flight.notify.notify_waiters();
        let mut state = self.state.lock().await;
        if state
            .in_flight
            .get(client_id)
            .is_some_and(|current| Arc::ptr_eq(current, &in_flight))
        {
            state.in_flight.remove(client_id);
        }
        state.governor.release(origin);
    }
}

enum ResolutionPlan {
    Existing(Box<OAuthProviderClient>),
    Cached(CimdMetadata),
    Join(Arc<InFlight>),
    Fetch {
        in_flight: Arc<InFlight>,
        cached: Box<Option<CacheEntry>>,
        origin: String,
    },
}

async fn wait_for(in_flight: Arc<InFlight>) -> ResolutionResult {
    loop {
        let notified = in_flight.notify.notified();
        if let Some(result) = in_flight.result.lock().await.clone() {
            return result;
        }
        notified.await;
    }
}

impl From<AuthError> for ResolutionFailure {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::OAuthProvider(OAuthProviderError::InvalidClient(description)) => {
                Self::Invalid(description)
            }
            AuthError::OAuthProvider(
                OAuthProviderError::TooManyRequestsTemporarilyUnavailable(description),
            ) => Self::TemporarilyUnavailable(description),
            error => Self::Server(error.to_string()),
        }
    }
}

impl ResolutionFailure {
    fn into_auth_error(self) -> AuthError {
        match self {
            Self::Invalid(description) => OAuthProviderError::InvalidClient(description).into(),
            Self::TemporarilyUnavailable(description) => {
                OAuthProviderError::TooManyRequestsTemporarilyUnavailable(description).into()
            }
            Self::Server(description) => OAuthProviderError::ServerError(description).into(),
        }
    }
}

#[async_trait]
impl OAuthProviderExtension for CimdClientDiscovery {
    fn bind_oauth_provider(
        &self,
        service: &crate::AuthService,
        config: Arc<OAuthProviderPluginConfig>,
        store: Arc<dyn OAuthProviderStore>,
    ) {
        *self.binding.write().expect("CIMD binding lock") = Some(ProviderBinding {
            service: service.clone(),
            config,
            store,
        });
    }

    fn client_discovery_ids(&self) -> Vec<String> {
        vec!["cimd".into()]
    }

    fn client_discovery_metadata(&self) -> Map<String, Value> {
        Map::from_iter([("client_id_metadata_document_supported".into(), json!(true))])
    }

    async fn discover_client(
        &self,
        client_id: &str,
        stored_client: Option<&OAuthProviderClient>,
        context: &OAuthCallbackContext,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        self.resolve(client_id, stored_client, context)
            .await
            .map_err(ResolutionFailure::into_auth_error)
    }

    async fn fetch_client_metadata_resource(
        &self,
        discovery_id: &str,
        uri: &str,
    ) -> Result<Option<OAuthClientMetadataResourceResponse>, AuthError> {
        if discovery_id != "cimd" { return Ok(None); }
        let response = self.options.fetch_client_metadata_resource.fetch(CimdFetchRequest {
            url: uri.into(),
            method: "GET".into(),
            headers: BTreeMap::from([("accept".into(), "application/json".into())]),
            timeout: FETCH_TIMEOUT,
            maximum_response_bytes: MAX_RESOURCE_BYTES,
        }).await.map_err(|error| OAuthProviderError::InvalidClient(error.to_string()))?;
        if response.redirected {
            return Err(OAuthProviderError::InvalidClient(
                "client metadata resource fetch must not follow redirects".into(),
            ).into());
        }
        Ok(Some(OAuthClientMetadataResourceResponse {
            status: response.status,
            content_type: response.content_type().map(str::to_owned),
            body: response.body,
        }))
    }
}
