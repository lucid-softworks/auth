use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, CreemCheckout, CreemCheckoutRequest, CreemOptions, CreemPlugin,
    CreemPortal, CreemPortalRequest, CreemProviderConfig, CreemProviderError,
    CreemProviderSubscription, CreemTransactionPage, CreemTransactionSearch, CreemTransport,
    MemoryCreemStore, MemoryStore, NewPasswordUser,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CreemCall {
    Checkout(CreemCheckoutRequest),
    Portal(CreemPortalRequest),
    Cancel(String),
    Retrieve(String),
    Search(CreemTransactionSearch),
}

pub(crate) struct FakeCreemTransport {
    config: CreemProviderConfig,
    calls: Mutex<Vec<CreemCall>>,
    failure: Mutex<Option<CreemProviderError>>,
    checkout_url: Mutex<Option<String>>,
}

impl Default for FakeCreemTransport {
    fn default() -> Self {
        Self {
            config: CreemProviderConfig::test("contract-key"),
            calls: Mutex::new(Vec::new()),
            failure: Mutex::new(None),
            checkout_url: Mutex::new(Some("https://checkout.creem.test/session".into())),
        }
    }
}

impl FakeCreemTransport {
    pub(crate) async fn calls(&self) -> Vec<CreemCall> {
        self.calls.lock().await.clone()
    }

    pub(crate) async fn fail_next(&self, message: &str) {
        *self.failure.lock().await = Some(CreemProviderError::new(message));
    }

    pub(crate) async fn set_checkout_url(&self, url: Option<&str>) {
        *self.checkout_url.lock().await = url.map(str::to_owned);
    }

    async fn record(&self, call: CreemCall) -> Result<(), CreemProviderError> {
        self.calls.lock().await.push(call);
        if let Some(error) = self.failure.lock().await.take() {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl CreemTransport for FakeCreemTransport {
    fn config(&self) -> &CreemProviderConfig {
        &self.config
    }

    async fn create_checkout(
        &self,
        request: CreemCheckoutRequest,
    ) -> Result<CreemCheckout, CreemProviderError> {
        self.record(CreemCall::Checkout(request)).await?;
        Ok(CreemCheckout {
            checkout_url: self.checkout_url.lock().await.clone(),
            value: json!({"id": "checkout_contract"}),
        })
    }

    async fn create_portal(
        &self,
        request: CreemPortalRequest,
    ) -> Result<CreemPortal, CreemProviderError> {
        self.record(CreemCall::Portal(request)).await?;
        Ok(CreemPortal {
            customer_portal_link: "https://portal.creem.test/customer".into(),
            value: json!({"customerPortalLink": "https://portal.creem.test/customer"}),
        })
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<CreemProviderSubscription, CreemProviderError> {
        self.record(CreemCall::Cancel(subscription_id.into()))
            .await?;
        Ok(CreemProviderSubscription {
            value: json!({"id": subscription_id}),
        })
    }

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<CreemProviderSubscription, CreemProviderError> {
        self.record(CreemCall::Retrieve(subscription_id.into()))
            .await?;
        Ok(CreemProviderSubscription {
            value: json!({"id": subscription_id, "status": "active"}),
        })
    }

    async fn search_transactions(
        &self,
        search: CreemTransactionSearch,
    ) -> Result<CreemTransactionPage, CreemProviderError> {
        self.record(CreemCall::Search(search)).await?;
        Ok(CreemTransactionPage {
            value: json!({"items": [], "pagination": {"nextPage": null}}),
            next_page: None,
        })
    }
}

pub(crate) struct Fixture {
    pub app: Router,
    pub transport: Arc<FakeCreemTransport>,
    pub store: Arc<MemoryCreemStore>,
    pub cookie: Option<String>,
    pub user_id: Option<String>,
}

pub(crate) async fn fixture<F>(api_key: &str, authenticated: bool, configure: F) -> Fixture
where
    F: FnOnce(&mut CreemOptions),
{
    let transport = Arc::new(FakeCreemTransport::default());
    let auth_store = Arc::new(MemoryStore::default());
    let store = Arc::new(MemoryCreemStore::new(auth_store.clone()));
    let mut options = CreemOptions::with_transport(api_key, transport.clone());
    configure(&mut options);
    let mut config = AuthConfig::new([49_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(CreemPlugin::new(options, store.clone()))
        .unwrap();
    let service = Arc::new(AuthService::try_new(auth_store, config).unwrap());

    let (cookie, user_id) = if authenticated {
        let user = service
            .provision_password_user(NewPasswordUser {
                username: "creem_contract_owner".into(),
                name: "Creem Contract Owner".into(),
                email: Some("owner@example.test".into()),
                password: "correct horse battery staple".into(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        let signed_in = service
            .sign_in_username(
                "creem_contract_owner",
                "correct horse battery staple".into(),
                None,
                None,
            )
            .await
            .unwrap();
        (
            Some(format!(
                "better-auth.session_token={}",
                service.signed_cookie_value(&signed_in.token)
            )),
            Some(user.id),
        )
    } else {
        (None, None)
    };

    Fixture {
        app: lucid_auth::axum::router(service),
        transport,
        store,
        cookie,
        user_id,
    }
}

pub(crate) async fn post(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let mut request = Request::post(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = &fixture.cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(
        &fixture.app,
        request.body(Body::from(body.to_string())).unwrap(),
    )
    .await
}

pub(crate) async fn post_with_headers(
    fixture: &Fixture,
    path: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut request = Request::post(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = &fixture.cookie {
        request = request.header(header::COOKIE, cookie);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    send(
        &fixture.app,
        request.body(Body::from(body.to_string())).unwrap(),
    )
    .await
}

pub(crate) async fn get(fixture: &Fixture, path: &str) -> (StatusCode, Value) {
    let mut request = Request::get(path).header(header::ORIGIN, "http://localhost");
    if let Some(cookie) = &fixture.cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(&fixture.app, request.body(Body::empty()).unwrap()).await
}

pub(crate) async fn raw_post(
    fixture: &Fixture,
    path: &str,
    body: &str,
    signature: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(signature) = signature {
        request = request.header("creem-signature", signature);
    }
    send(
        &fixture.app,
        request.body(Body::from(body.to_owned())).unwrap(),
    )
    .await
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}
