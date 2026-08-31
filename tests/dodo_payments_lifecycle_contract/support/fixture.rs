use super::LifecycleClient;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, AuthStore, DodoCustomerParams, DodoCustomerParamsProvider,
    DodoPaymentsCallbackError, DodoPaymentsFeature, DodoPaymentsOptions, DodoPaymentsPlugin,
    DodoUser, MemoryStore, NewPasswordUser,
};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

pub(crate) struct Fixture {
    pub(crate) app: Router,
    pub(crate) client: Arc<LifecycleClient>,
    pub(crate) store: Arc<MemoryStore>,
    pub(crate) user_id: String,
    cookie: String,
}

struct CustomerParams;

#[async_trait::async_trait]
impl DodoCustomerParamsProvider for CustomerParams {
    async fn params(
        &self,
        _user: &DodoUser,
    ) -> Result<DodoCustomerParams, DodoPaymentsCallbackError> {
        Ok(DodoCustomerParams {
            metadata: Some(BTreeMap::from([("source".into(), "lazy-route".into())])),
            phone_number: Some(None),
        })
    }
}

pub(crate) async fn fixture(customer_id: Option<&str>) -> Fixture {
    let client = Arc::new(LifecycleClient::new(customer_id));
    let store = Arc::new(MemoryStore::default());
    let mut options = DodoPaymentsOptions::new(
        client.clone(),
        vec![DodoPaymentsFeature::Portal, DodoPaymentsFeature::Usage],
    );
    options.get_customer_params = Some(Arc::new(CustomerParams));
    let mut config = AuthConfig::new([73_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(DodoPaymentsPlugin::new(options, store.clone()))
        .unwrap();
    let service = Arc::new(AuthService::try_new(store.clone(), config).unwrap());
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "dodo_lifecycle_owner".into(),
            name: "Lifecycle Owner".into(),
            email: Some("lifecycle@example.test".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    store
        .update_user_email(&user.id, &user.email, &user.email, true)
        .await
        .unwrap();
    let session = service
        .sign_in_username(
            "dodo_lifecycle_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&session.token)
    );

    Fixture {
        app: lucid_auth::axum::router(service),
        client,
        store,
        user_id: user.id,
        cookie,
    }
}

pub(crate) async fn get(fixture: &Fixture, path: &str) -> (StatusCode, Value) {
    send(
        fixture,
        Request::get(path)
            .header(header::HOST, "app.example.test")
            .header(header::ORIGIN, "http://localhost")
            .header(header::COOKIE, &fixture.cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

pub(crate) async fn post(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    send(
        fixture,
        Request::post(path)
            .header(header::HOST, "app.example.test")
            .header(header::ORIGIN, "http://localhost")
            .header(header::COOKIE, &fixture.cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

async fn send(fixture: &Fixture, request: Request<Body>) -> (StatusCode, Value) {
    let response = fixture.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}
