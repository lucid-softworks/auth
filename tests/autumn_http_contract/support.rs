use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, AutumnClient, AutumnCustomerScope, AutumnOperation, AutumnOptions,
    AutumnPlugin, AutumnProviderError, MemoryOrganizationStore, MemoryStore, NewOrganization,
    NewPasswordUser, OrganizationPlugin,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;
use url::Url;

#[derive(Default)]
pub(crate) struct FakeAutumnClient {
    calls: Mutex<Vec<(AutumnOperation, Value, String, Url)>>,
    failure: Mutex<Option<AutumnProviderError>>,
}

impl FakeAutumnClient {
    pub(crate) async fn calls(&self) -> Vec<(AutumnOperation, Value, String, Url)> {
        self.calls.lock().await.clone()
    }

    pub(crate) async fn fail_next(&self, error: AutumnProviderError) {
        *self.failure.lock().await = Some(error);
    }
}

#[async_trait]
impl AutumnClient for FakeAutumnClient {
    async fn execute(
        &self,
        operation: AutumnOperation,
        request: Value,
        secret_key: &str,
        base_url: &Url,
    ) -> Result<Value, AutumnProviderError> {
        self.calls.lock().await.push((
            operation,
            request.clone(),
            secret_key.into(),
            base_url.clone(),
        ));
        if let Some(error) = self.failure.lock().await.take() {
            return Err(error);
        }
        Ok(json!({"operation": format!("{operation:?}"), "request": request}))
    }
}

pub(crate) struct Fixture {
    pub app: Router,
    pub client: Arc<FakeAutumnClient>,
    pub cookie: String,
    pub user_id: uuid::Uuid,
}

pub(crate) async fn fixture() -> Fixture {
    user_fixture(AutumnCustomerScope::User).await
}

pub(crate) async fn user_fixture(scope: AutumnCustomerScope) -> Fixture {
    let client = Arc::new(FakeAutumnClient::default());
    let mut options = AutumnOptions::with_client(client.clone());
    options.secret_key = Some("autumn_contract_key".into());
    options.base_url = Some("https://autumn.example.test/prefix".into());
    options.customer_scope = scope;
    let mut config = AuthConfig::new([82_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(AutumnPlugin::new(options)).unwrap();
    let service = Arc::new(
        AuthService::try_new(Arc::new(MemoryStore::default()), config)
            .expect("Autumn plugin configuration is valid"),
    );
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "autumn_owner".into(),
            name: "Autumn Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username(
            "autumn_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&signed_in.token)
    );
    Fixture {
        app: lucid_auth::axum::router(service),
        client,
        cookie,
        user_id: user.id,
    }
}

pub(crate) async fn organization_fixture(scope: AutumnCustomerScope) -> (Fixture, uuid::Uuid) {
    let client = Arc::new(FakeAutumnClient::default());
    let mut options = AutumnOptions::with_client(client.clone());
    options.secret_key = Some("autumn_organization_key".into());
    options.customer_scope = scope;
    let mut config = AuthConfig::new([86_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(OrganizationPlugin::new(Arc::new(
            MemoryOrganizationStore::default(),
        )))
        .unwrap();
    config.add_plugin(AutumnPlugin::new(options)).unwrap();
    let service = Arc::new(
        AuthService::try_new(Arc::new(MemoryStore::default()), config)
            .expect("Autumn and Organization plugins compose"),
    );
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "autumn_org_owner".into(),
            name: "Autumn Org Owner".into(),
            email: Some("org-owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username(
            "autumn_org_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let session = service.session(&signed_in.token).await.unwrap().unwrap();
    let created = service
        .create_organization(
            &session,
            NewOrganization {
                name: "Autumn Organization".into(),
                slug: "autumn-organization".into(),
                logo: None,
                metadata: None,
                keep_current_active_organization: false,
            },
        )
        .await
        .unwrap();
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&signed_in.token)
    );
    (
        Fixture {
            app: lucid_auth::axum::router(service),
            client,
            cookie,
            user_id: user.id,
        },
        created.organization.id,
    )
}

pub(crate) fn app_with_options(options: AutumnOptions, secret: [u8; 32]) -> Router {
    let mut config = AuthConfig::new(secret).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(AutumnPlugin::new(options)).unwrap();
    lucid_auth::axum::router(Arc::new(
        AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap(),
    ))
}

pub(crate) async fn post(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::post(path).header(header::ORIGIN, "http://localhost");
    let body = match body {
        Some(body) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}
