use axum::{
    Router,
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, AxumPluginRoute, ExpoOptions, ExpoPlugin, MemoryStore,
    PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginProvenance,
};
use std::{borrow::Cow, sync::Arc};

const REDIRECT_ENDPOINTS: &[PluginEndpoint] = &[
    endpoint("/magic-link/verify-oracle", "fixture.magicLink"),
    endpoint("/verify-email-oracle", "fixture.verifyEmail"),
    endpoint("/callback-oracle", "fixture.callback"),
    endpoint("/unrelated-redirect", "fixture.unrelated"),
];

const fn endpoint(path: &'static str, client_method: &'static str) -> PluginEndpoint {
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: Cow::Borrowed(path),
        client_method,
    }
}

pub(super) fn application(options: Option<ExpoOptions>) -> (Router, Arc<AuthService>) {
    application_with_redirects(options, false)
}

pub(super) fn application_with_redirects(
    options: Option<ExpoOptions>,
    redirects: bool,
) -> (Router, Arc<AuthService>) {
    let mut config = AuthConfig::new([b'E'; 32]).unwrap();
    config
        .set_base_url("https://auth.example/api/auth")
        .unwrap();
    config.email_and_password.enabled = true;
    config.trust_origin("oracle://").unwrap();
    config.trust_origin("https://web.example").unwrap();
    if let Some(options) = options {
        config.add_plugin(ExpoPlugin::new(options)).unwrap();
    }
    if redirects {
        config.add_plugin(RedirectFixture).unwrap();
    }
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    (lucid_auth::axum::router(service.clone()), service)
}

pub(super) async fn body_json(response: Response) -> serde_json::Value {
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[derive(Debug)]
struct RedirectFixture;

#[async_trait::async_trait]
impl AuthPlugin for RedirectFixture {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "expo-redirect-fixture",
            display_name: "Expo redirect fixture",
            version: "1.0.0",
            provenance: PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(REDIRECT_ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        vec![
            AxumPluginRoute::new(
                "/magic-link/verify-oracle",
                axum::routing::get(trusted_redirect),
            ),
            AxumPluginRoute::new(
                "/verify-email-oracle",
                axum::routing::get(untrusted_redirect),
            ),
            AxumPluginRoute::new("/callback-oracle", axum::routing::get(http_redirect)),
            AxumPluginRoute::new("/unrelated-redirect", axum::routing::get(trusted_redirect)),
        ]
    }
}

async fn trusted_redirect() -> Response {
    redirect(
        "oracle:///complete?existing=yes&cookie=stale&cookie=duplicate",
        true,
    )
}

async fn untrusted_redirect() -> Response {
    redirect("evil:///complete", true)
}

async fn http_redirect() -> Response {
    redirect("https://web.example/complete", true)
}

fn redirect(location: &'static str, cookies: bool) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(location));
    if cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static("better-auth.session_token=signed; HttpOnly; Path=/"),
        );
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static("better-auth.session_data=cached; HttpOnly; Path=/"),
        );
    }
    response
}
