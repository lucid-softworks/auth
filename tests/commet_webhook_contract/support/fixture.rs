use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, CommetFeature, CommetHttpClient, CommetOptions, CommetPlugin,
    CommetProviderConfig, CommetWebhookCallbacks, CommetWebhooksOptions, MemoryStore,
    sign_commet_webhook,
};
use std::sync::Arc;
use tower::ServiceExt;

pub(crate) const SECRET: &str = "commet-webhook-contract-secret";

pub(crate) struct WebhookFixture {
    app: Router,
}

#[derive(Debug)]
pub(crate) struct WebhookResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: String,
}

pub(crate) fn fixture(callbacks: CommetWebhookCallbacks) -> WebhookFixture {
    let client = Arc::new(CommetHttpClient::new(
        CommetProviderConfig::new("ck_unused-webhook-api-key").unwrap(),
    ));
    let mut webhooks = CommetWebhooksOptions::new(SECRET);
    webhooks.callbacks = callbacks;
    let plugin = CommetPlugin::new(CommetOptions::new(
        client,
        vec![CommetFeature::Webhooks(webhooks)],
    ));
    let mut config = AuthConfig::new([82_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(plugin).unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    WebhookFixture {
        app: lucid_auth::axum::router(service),
    }
}

impl WebhookFixture {
    pub(crate) async fn send(&self, request: Request<Body>) -> WebhookResponse {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        WebhookResponse {
            status,
            headers,
            body: String::from_utf8(bytes.to_vec()).unwrap(),
        }
    }
}

pub(crate) fn raw_request(content_type: Option<&str>, body: &str) -> Request<Body> {
    let mut request = Request::post("/api/auth/commet/webhooks");
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    request.body(Body::from(body.to_owned())).unwrap()
}

pub(crate) fn signed_request(body: &str, signature: Option<&str>) -> Request<Body> {
    let signature = signature
        .map(str::to_owned)
        .unwrap_or_else(|| sign_commet_webhook(body, SECRET));
    Request::post("/api/auth/commet/webhooks")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-commet-signature", signature)
        .body(Body::from(body.to_owned()))
        .unwrap()
}
