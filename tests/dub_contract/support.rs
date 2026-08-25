use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AccessStore, AuthConfig, AuthService, AuthStore, DubLead, DubLeadError, DubLeadTracker,
    DubOAuthOptions, DubOptions, DubPlugin, MemoryStore,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) const DELETE_COOKIE: &str = "dub_id=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";

#[derive(Clone)]
pub(crate) struct RecordingTracker {
    store: Arc<MemoryStore>,
    calls: Arc<Mutex<Vec<DubLead>>>,
    reject: bool,
}

impl RecordingTracker {
    pub(crate) fn new(store: Arc<MemoryStore>, reject: bool) -> Self {
        Self {
            store,
            calls: Arc::new(Mutex::new(Vec::new())),
            reject,
        }
    }

    pub(crate) async fn calls(&self) -> Vec<DubLead> {
        self.calls.lock().await.clone()
    }
}

#[async_trait]
impl DubLeadTracker for RecordingTracker {
    async fn track_lead(&self, lead: &DubLead) -> Result<(), DubLeadError> {
        let user_id = Uuid::parse_str(&lead.customer_external_id).unwrap();
        assert!(
            self.store.find_user_by_id(user_id).await.unwrap().is_some(),
            "Dub runs after user persistence"
        );
        assert!(
            self.store
                .find_password_hash(user_id)
                .await
                .unwrap()
                .is_some(),
            "Dub runs after credential-account persistence"
        );
        assert_eq!(
            self.store.list_sessions(user_id).await.unwrap().len(),
            1,
            "Dub runs after session persistence"
        );
        self.calls.lock().await.push(lead.clone());
        if self.reject {
            Err(DubLeadError::new("provider rejected"))
        } else {
            Ok(())
        }
    }
}

pub(crate) struct Fixture {
    pub(crate) app: Router,
    pub(crate) store: Arc<MemoryStore>,
    pub(crate) tracker: Arc<RecordingTracker>,
}

pub(crate) fn fixture(reject: bool, configure: impl FnOnce(&mut DubOptions)) -> Fixture {
    let store = Arc::new(MemoryStore::default());
    let tracker = Arc::new(RecordingTracker::new(store.clone(), reject));
    let mut options = DubOptions::new(tracker.clone());
    configure(&mut options);
    let mut config = AuthConfig::new([53_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.email_and_password.enabled = true;
    config.add_plugin(DubPlugin::new(options)).unwrap();
    let service = Arc::new(AuthService::new(store.clone(), config));
    Fixture {
        app: lucid_auth::axum::router(service),
        store,
        tracker,
    }
}

pub(crate) fn configured_oauth(options: &mut DubOptions) {
    options.oauth = Some(DubOAuthOptions::new("client", "client-secret"));
}

pub(crate) async fn send(
    app: &Router,
    mut request: Request<Body>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    request
        .headers_mut()
        .entry(header::CONTENT_TYPE)
        .or_insert(axum::http::HeaderValue::from_static("application/json"));
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

pub(crate) fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

pub(crate) fn set_cookies(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect()
}
