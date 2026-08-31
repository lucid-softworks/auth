use super::support::*;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

#[derive(Clone)]
struct RecordedFetcher {
    requests: Arc<Mutex<Vec<CimdFetchRequest>>>,
    responses: Arc<Mutex<VecDeque<CimdFetchResponse>>>,
    delay: StdDuration,
}

impl RecordedFetcher {
    fn new(responses: impl IntoIterator<Item = CimdFetchResponse>) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            delay: StdDuration::ZERO,
        }
    }

    fn delayed(mut self) -> Self {
        self.delay = StdDuration::from_millis(50);
        self
    }
}

#[async_trait]
impl CimdMetadataResourceFetcher for RecordedFetcher {
    async fn fetch(&self, request: CimdFetchRequest) -> Result<CimdFetchResponse, CimdFetchError> {
        self.requests.lock().unwrap().push(request);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| CimdFetchError::new("unexpected extra fetch"))
    }
}

#[derive(Default)]
struct LifecycleRecorder {
    created: AtomicUsize,
    refreshed: AtomicUsize,
    previous: Mutex<Option<OAuthProviderClient>>,
}

#[async_trait]
impl CimdClientLifecycle for LifecycleRecorder {
    async fn created(&self, _event: CimdClientCreatedEvent) -> Result<(), AuthError> {
        self.created.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn refreshed(&self, event: CimdClientRefreshedEvent) -> Result<(), AuthError> {
        self.refreshed.fetch_add(1, Ordering::SeqCst);
        *self.previous.lock().unwrap() = Some(event.previous_client);
        Ok(())
    }
}

struct CimdFixture {
    app: Router,
    oauth: Arc<MemoryOAuthProviderStore>,
}

async fn fixture_with_cimd(options: CimdOptions) -> CimdFixture {
    let oauth = Arc::new(MemoryOAuthProviderStore::new());
    fixture_with_cimd_store(options, oauth, 119).await
}

async fn fixture_with_cimd_store(
    options: CimdOptions,
    oauth: Arc<MemoryOAuthProviderStore>,
    secret: u8,
) -> CimdFixture {
    let mut config = AuthConfig::new([secret; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(JwtPlugin::default()).unwrap();
    config
        .add_plugin(OAuthProviderPlugin::from_arc(
            OAuthProviderPluginConfig::new("/login", "/consent"),
            oauth.clone() as Arc<_>,
        ))
        .unwrap();
    config.add_plugin(cimd(options).unwrap()).unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    CimdFixture {
        app: lucid_auth::axum::router(service),
        oauth,
    }
}

async fn fixture_without_cimd(oauth: Arc<MemoryOAuthProviderStore>) -> CimdFixture {
    let mut config = AuthConfig::new([120_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(JwtPlugin::default()).unwrap();
    config
        .add_plugin(OAuthProviderPlugin::from_arc(
            OAuthProviderPluginConfig::new("/login", "/consent"),
            oauth.clone() as Arc<_>,
        ))
        .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    CimdFixture {
        app: lucid_auth::axum::router(service),
        oauth,
    }
}

fn metadata_response(client_id: &str, name: &str, cache_control: &str) -> CimdFetchResponse {
    CimdFetchResponse {
        status: 200,
        headers: BTreeMap::from([
            (
                "Content-Type".into(),
                "application/metadata+json; charset=utf-8".into(),
            ),
            ("Cache-Control".into(), cache_control.into()),
            ("ETag".into(), "\"document-v1\"".into()),
        ]),
        body: json!({
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": ["https://client.example/callback"],
            "future_extension": "stripped"
        })
        .to_string()
        .into_bytes(),
        redirected: false,
    }
}

fn metadata_response_with_grants(client_id: &str, grants: &[&str]) -> CimdFetchResponse {
    let mut response = metadata_response(client_id, "CIMD grants", "max-age=60");
    let mut metadata: Value = serde_json::from_slice(&response.body).unwrap();
    metadata["grant_types"] = json!(grants);
    response.body = serde_json::to_vec(&metadata).unwrap();
    response
}

async fn authorize(app: &Router, client_id: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", "https://client.example/callback")
        .append_pair("scope", "openid")
        .finish();
    request(
        app,
        "GET",
        &format!("/api/auth/oauth2/authorize?{query}"),
        None,
        Body::empty(),
        None,
    )
    .await
}

fn redirect_error(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .and_then(|url| {
            url.query_pairs()
                .find(|(name, _)| name == "error")
                .map(|(_, value)| value.into_owned())
        })
}

#[tokio::test]
async fn discovery_is_advertised_and_persists_once_for_a_fresh_cache_hit() {
    let client_id = "https://metadata.example/client.json";
    let fetcher = RecordedFetcher::new([metadata_response(client_id, "CIMD client", "max-age=60")]);
    let lifecycle = Arc::new(LifecycleRecorder::default());
    let mut options = CimdOptions::new(Arc::new(fetcher.clone()));
    options.lifecycle = Some(lifecycle.clone());
    let fixture = fixture_with_cimd(options).await;

    let (status, _, metadata) = json_request(
        &fixture.app,
        "GET",
        "/.well-known/oauth-authorization-server/api/auth",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{metadata}");
    assert_eq!(metadata["client_id_metadata_document_supported"], true);

    assert_eq!(
        authorize(&fixture.app, client_id).await.0,
        StatusCode::FOUND
    );
    assert_eq!(
        authorize(&fixture.app, client_id).await.0,
        StatusCode::FOUND
    );
    assert_eq!(fetcher.requests.lock().unwrap().len(), 1);
    assert_eq!(lifecycle.created.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.refreshed.load(Ordering::SeqCst), 0);

    let stored = fixture
        .oauth
        .find_oauth_client(client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_id, client_id);
    assert_eq!(stored.client_discovery_id.as_deref(), Some("cimd"));
    assert_eq!(stored.name.as_deref(), Some("CIMD client"));
    assert_eq!(stored.token_endpoint_auth_method.as_deref(), Some("none"));
    assert!(stored.client_secret.is_none());
    assert!(stored.application_type.is_none());
    assert!(stored.client_credentials_scopes.is_empty());
}

#[tokio::test]
async fn cimd_grants_intersect_with_provider_support_instead_of_requiring_equality() {
    let client_id = "https://metadata.example/grant-intersection.json";
    let fetcher = RecordedFetcher::new([metadata_response_with_grants(
        client_id,
        &["authorization_code", "unsupported_custom_grant"],
    )]);
    let fixture = fixture_with_cimd(CimdOptions::new(Arc::new(fetcher))).await;

    assert_eq!(
        authorize(&fixture.app, client_id).await.0,
        StatusCode::FOUND
    );
    let stored = fixture
        .oauth
        .find_oauth_client(client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.grant_types.unwrap(),
        ["authorization_code", "unsupported_custom_grant"]
    );
}

#[tokio::test]
async fn expired_entries_revalidate_conditionally_and_preserve_operator_fields() {
    let client_id = "https://metadata.example/revalidated.json";
    let not_modified = CimdFetchResponse {
        status: 304,
        headers: BTreeMap::from([("Cache-Control".into(), "max-age=0".into())]),
        body: Vec::new(),
        redirected: false,
    };
    let fetcher = RecordedFetcher::new([
        metadata_response(client_id, "Original", "max-age=0"),
        not_modified.clone(),
        CimdFetchResponse {
            headers: BTreeMap::from([("Cache-Control".into(), "max-age=60".into())]),
            ..not_modified
        },
    ]);
    let lifecycle = Arc::new(LifecycleRecorder::default());
    let mut options = CimdOptions::new(Arc::new(fetcher.clone()));
    options.metadata_fetch_policy.minimum_fetch_interval = 0_u64.into();
    options.lifecycle = Some(lifecycle.clone());
    let fixture = fixture_with_cimd(options).await;

    assert_eq!(
        authorize(&fixture.app, client_id).await.0,
        StatusCode::FOUND
    );
    let mut operator_update = fixture
        .oauth
        .find_oauth_client(client_id)
        .await
        .unwrap()
        .unwrap();
    operator_update.disabled = true;
    operator_update.skip_consent = Some(true);
    operator_update.enable_end_session = Some(true);
    operator_update.client_credentials_scopes = vec!["operator.scope".into()];
    fixture
        .oauth
        .update_oauth_client(operator_update.clone())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        authorize(&fixture.app, client_id).await.0,
        StatusCode::FOUND
    );
    {
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for request in &requests[1..] {
            assert_eq!(
                request.headers.get("if-none-match").map(String::as_str),
                Some("\"document-v1\"")
            );
        }
    }
    assert_eq!(lifecycle.created.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.refreshed.load(Ordering::SeqCst), 2);
    let previous = lifecycle.previous.lock().unwrap().clone().unwrap();
    assert!(previous.disabled);
    assert_eq!(previous.client_credentials_scopes, ["operator.scope"]);

    let stored = fixture
        .oauth
        .find_oauth_client(client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.disabled);
    assert_eq!(stored.skip_consent, Some(true));
    assert_eq!(stored.enable_end_session, Some(true));
    assert_eq!(stored.client_credentials_scopes, ["operator.scope"]);
}

#[tokio::test]
async fn same_client_concurrency_coalesces_to_one_fetch() {
    let client_id = "https://metadata.example/coalesced.json";
    let fetcher =
        RecordedFetcher::new([metadata_response(client_id, "Coalesced", "max-age=60")]).delayed();
    let fixture = fixture_with_cimd(CimdOptions::new(Arc::new(fetcher.clone()))).await;

    let (first, second) = tokio::join!(
        authorize(&fixture.app, client_id),
        authorize(&fixture.app, client_id),
    );
    assert_eq!(first.0, StatusCode::FOUND);
    assert_eq!(second.0, StatusCode::FOUND);
    assert_eq!(fetcher.requests.lock().unwrap().len(), 1);
    assert!(
        fixture
            .oauth
            .find_oauth_client(client_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn managed_clients_cannot_be_taken_over_by_cimd() {
    let client_id = "https://metadata.example/managed.json";
    let fetcher = RecordedFetcher::new([]);
    let fixture = fixture_with_cimd(CimdOptions::new(Arc::new(fetcher.clone()))).await;
    let managed = fixture
        .oauth
        .persist_oauth_client_registration(
            &oauth_record_id,
            &oauth_record_id,
            OAuthClientRegistrationWrite {
                client: client(client_id, None),
                resource_ids: Vec::new(),
                mode: OAuthClientRegistrationMode::Create,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        managed,
        OAuthClientRegistrationOutcome::Created(_)
    ));

    assert_eq!(
        authorize(&fixture.app, client_id).await.0,
        StatusCode::FOUND
    );
    assert!(fetcher.requests.lock().unwrap().is_empty());
    let stored = fixture
        .oauth
        .find_oauth_client(client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.client_discovery_id.is_none());
}

#[tokio::test]
async fn removed_discovery_owner_fails_closed_without_rewriting_the_client() {
    let client_id = "https://metadata.example/orphaned.json";
    let oauth = Arc::new(MemoryOAuthProviderStore::new());
    let mut discovered = client(client_id, None);
    discovered.client_discovery_id = Some("cimd".into());
    oauth
        .persist_oauth_client_registration(
            &oauth_record_id,
            &oauth_record_id,
            OAuthClientRegistrationWrite {
                client: discovered,
                resource_ids: Vec::new(),
                mode: OAuthClientRegistrationMode::Create,
            },
        )
        .await
        .unwrap();
    let fixture = fixture_without_cimd(oauth).await;

    let (status, headers, _) = authorize(&fixture.app, client_id).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(redirect_error(&headers).as_deref(), Some("invalid_client"));
    let stored = fixture
        .oauth
        .find_oauth_client(client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.client_discovery_id.as_deref(), Some("cimd"));
}

#[tokio::test]
async fn stale_fetch_failure_leaves_the_last_valid_registration_intact() {
    let client_id = "https://metadata.example/stale.json";
    let fetcher = RecordedFetcher::new([metadata_response(client_id, "Stored", "max-age=0")]);
    let mut options = CimdOptions::new(Arc::new(fetcher.clone()));
    options.metadata_fetch_policy.minimum_fetch_interval = 0_u64.into();
    let fixture = fixture_with_cimd(options).await;

    let (status, _, body) = authorize(&fixture.app, client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "invalid_client");
    assert_eq!(fetcher.requests.lock().unwrap().len(), 2);
    let stored = fixture
        .oauth
        .find_oauth_client(client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.name.as_deref(), Some("Stored"));
    assert_eq!(stored.client_discovery_id.as_deref(), Some("cimd"));
}

#[tokio::test]
async fn same_owner_creation_race_converges_through_canonical_registration() {
    let client_id = "https://metadata.example/race.json";
    let lifecycle = Arc::new(LifecycleRecorder::default());
    let response = || metadata_response(client_id, "Racing client", "max-age=60");
    let first_fetcher = RecordedFetcher::new([response()]).delayed();
    let second_fetcher = RecordedFetcher::new([response()]).delayed();
    let mut first_options = CimdOptions::new(Arc::new(first_fetcher.clone()));
    first_options.lifecycle = Some(lifecycle.clone());
    let mut second_options = CimdOptions::new(Arc::new(second_fetcher.clone()));
    second_options.lifecycle = Some(lifecycle.clone());
    let oauth = Arc::new(MemoryOAuthProviderStore::new());
    let first = fixture_with_cimd_store(first_options, oauth.clone(), 121).await;
    let second = fixture_with_cimd_store(second_options, oauth.clone(), 122).await;

    let (first_response, second_response) = tokio::join!(
        authorize(&first.app, client_id),
        authorize(&second.app, client_id),
    );
    assert_eq!(first_response.0, StatusCode::FOUND);
    assert_eq!(second_response.0, StatusCode::FOUND);
    assert_eq!(first_fetcher.requests.lock().unwrap().len(), 1);
    assert_eq!(second_fetcher.requests.lock().unwrap().len(), 1);
    assert_eq!(lifecycle.created.load(Ordering::SeqCst), 1);
    assert_eq!(lifecycle.refreshed.load(Ordering::SeqCst), 1);
    let stored = oauth.find_oauth_client(client_id).await.unwrap().unwrap();
    assert_eq!(stored.client_discovery_id.as_deref(), Some("cimd"));
    assert!(stored.client_secret.is_none());
}
