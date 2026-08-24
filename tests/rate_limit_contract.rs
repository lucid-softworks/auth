use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    routing::get,
};
use lucid_auth::{
    AuthConfig, AuthError, AuthPlugin, AuthService, AxumPluginRoute, MemoryStore, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, PluginRateLimit, RateLimitCustomRule, RateLimitOutcome,
    RateLimitRequest, RateLimitRule, RateLimitRuleResolver, RateLimitStorage, RateLimitStorageMode,
    SecurityStore,
};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};
use tower::ServiceExt;

fn application(configure: impl FnOnce(&mut AuthConfig)) -> Router {
    let mut config = AuthConfig::new([91_u8; 32]).unwrap();
    configure(&mut config);
    lucid_auth::axum::router(Arc::new(AuthService::new(
        Arc::new(MemoryStore::default()),
        config,
    )))
}

fn request(path: &str, peer: &str) -> Request<Body> {
    let peer = peer.parse::<SocketAddr>().unwrap();
    Request::get(path)
        .header("x-forwarded-for", peer.ip().to_string())
        .extension(ConnectInfo(peer))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn rolling_window_boundary_and_retry_seconds_match() {
    let store = MemoryStore::default();
    let now = chrono::Utc::now();
    let rule = RateLimitRule::new(10, 1);
    assert_eq!(
        store
            .consume_rate_limit("key", now, rule, 10)
            .await
            .unwrap(),
        RateLimitOutcome::allowed()
    );
    assert_eq!(
        store
            .consume_rate_limit("key", now + chrono::Duration::seconds(9), rule, 10)
            .await
            .unwrap(),
        RateLimitOutcome::denied(1)
    );
    assert_eq!(
        store
            .consume_rate_limit("key", now + chrono::Duration::seconds(10), rule, 10)
            .await
            .unwrap(),
        RateLimitOutcome::allowed()
    );
}

#[tokio::test]
async fn memory_limit_is_atomic_under_concurrency() {
    let app = application(|config| {
        config.rate_limit.enabled = true;
        config.rate_limit.max = 5;
    });
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            app.oneshot(request("/api/auth/get-session", "192.0.2.10:443"))
                .await
                .unwrap()
                .status()
        }));
    }
    let mut allowed = 0;
    let mut denied = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::OK => allowed += 1,
            StatusCode::TOO_MANY_REQUESTS => denied += 1,
            status => panic!("unexpected status {status}"),
        }
    }
    assert_eq!(allowed, 5);
    assert_eq!(denied, 15);
}

#[tokio::test]
async fn keys_are_isolated_by_normalized_ip_and_path() {
    let app = application(|config| {
        config.rate_limit.enabled = true;
        config.rate_limit.max = 1;
    });
    for peer in ["192.0.2.10:443", "192.0.2.11:443"] {
        assert_eq!(
            app.clone()
                .oneshot(request("/api/auth/get-session", peer))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(request("/api/auth/sign-out", "192.0.2.10:443"))
            .await
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        app.oneshot(request("/api/auth/get-session", "192.0.2.10:443"))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn missing_trusted_ip_uses_one_shared_path_bucket() {
    let app = application(|config| {
        config.rate_limit.enabled = true;
        config.rate_limit.max = 1;
    });
    let request = || {
        Request::get("/api/auth/get-session")
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn static_custom_rules_override_and_disable_limits() {
    let app = application(|config| {
        config.rate_limit.enabled = true;
        config.rate_limit.max = 1;
        config
            .rate_limit
            .custom_rules
            .push(RateLimitCustomRule::disabled("/get-session"));
    });
    for _ in 0..3 {
        assert_eq!(
            app.clone()
                .oneshot(request("/api/auth/get-session", "[2001:db8:1::1234]:443"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}

struct HeaderRule;

#[async_trait]
impl RateLimitRuleResolver for HeaderRule {
    async fn resolve(
        &self,
        request: &RateLimitRequest,
        current_rule: RateLimitRule,
    ) -> Result<Option<RateLimitRule>, AuthError> {
        assert_eq!(current_rule, RateLimitRule::new(10, 100));
        if request.headers.get("x-bypass").map(String::as_str) == Some("yes") {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/get-session");
            assert_eq!(request.query.as_deref(), Some("source=test"));
            Ok(None)
        } else {
            Ok(Some(RateLimitRule::new(30, 1)))
        }
    }
}

#[tokio::test]
async fn dynamic_custom_rules_receive_request_metadata() {
    let app = application(|config| {
        config.rate_limit.enabled = true;
        config
            .rate_limit
            .custom_rules
            .push(RateLimitCustomRule::dynamic(
                "/get-session",
                Arc::new(HeaderRule),
            ));
    });
    let bypass = || {
        let mut request = request("/api/auth/get-session?source=test", "192.0.2.10:443");
        request
            .headers_mut()
            .insert("x-bypass", "yes".parse().unwrap());
        request
    };
    assert_eq!(
        app.clone().oneshot(bypass()).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request("/api/auth/get-session", "192.0.2.10:443"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(request("/api/auth/get-session", "192.0.2.10:443"))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[derive(Default)]
struct DenySecond {
    count: AtomicU32,
}

#[async_trait]
impl RateLimitStorage for DenySecond {
    async fn consume(
        &self,
        _key: &str,
        rule: RateLimitRule,
    ) -> Result<RateLimitOutcome, AuthError> {
        assert_eq!(rule, RateLimitRule::new(10, 100));
        if self.count.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(RateLimitOutcome::allowed())
        } else {
            Ok(RateLimitOutcome::denied(7))
        }
    }
}

#[tokio::test]
async fn custom_storage_controls_atomic_consumption_and_retry_timing() {
    let storage = Arc::new(DenySecond::default());
    let app = application(|config| {
        config.rate_limit.enabled = true;
        config.rate_limit.storage = RateLimitStorageMode::Custom(storage);
    });
    assert_eq!(
        app.clone()
            .oneshot(request("/api/auth/get-session", "192.0.2.10:443"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let response = app
        .oneshot(request("/api/auth/get-session", "192.0.2.10:443"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["x-retry-after"], "7");
}

struct LimitedPlugin;

const PLUGIN_ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: std::borrow::Cow::Borrowed("/limited"),
    client_method: "limited.get",
}];
const PLUGIN_LIMITS: &[PluginRateLimit] = &[PluginRateLimit {
    path: "/limited",
    window: 30,
    max: 1,
}];

#[async_trait]
impl AuthPlugin for LimitedPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "limited",
            display_name: "Limited",
            version: "1.0.0",
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(PLUGIN_ENDPOINTS),
            cookies: &[],
            rate_limits: PLUGIN_LIMITS,
            middleware: &[],
            client: None,
        }
    }

    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        vec![AxumPluginRoute::new(
            "/limited",
            get(|| async { Json(json!({ "ok": true })) }),
        )]
    }
}

#[tokio::test]
async fn plugin_rules_override_the_global_rule() {
    let app = application(|config| {
        config.rate_limit.enabled = true;
        config.rate_limit.max = 100;
        config.add_plugin(LimitedPlugin).unwrap();
    });
    assert_eq!(
        app.clone()
            .oneshot(request("/api/auth/limited", "192.0.2.10:443"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(request("/api/auth/limited", "192.0.2.10:443"))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn disabled_ip_tracking_and_native_service_calls_opt_out() {
    let app = application(|config| {
        config.rate_limit.enabled = true;
        config.rate_limit.max = 1;
        config.ip_address.disable_ip_tracking = true;
    });
    for _ in 0..3 {
        assert_eq!(
            app.clone()
                .oneshot(request("/api/auth/get-session", "192.0.2.10:443"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    let mut config = AuthConfig::new([92_u8; 32]).unwrap();
    config.rate_limit.enabled = true;
    config.rate_limit.max = 1;
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    for _ in 0..3 {
        assert!(service.session("not-a-token").await.unwrap().is_none());
    }
}
