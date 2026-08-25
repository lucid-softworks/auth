use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request as AxumRequest, State},
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, CaptchaConfig, CaptchaFoxOptions, CaptchaPlugin,
    CloudflareTurnstileOptions, GoogleRecaptchaOptions, HCaptchaOptions, MemoryStore,
    RateLimitCustomRule,
};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

#[derive(Clone)]
struct ProviderState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    status: StatusCode,
    body: &'static str,
}

#[derive(Debug)]
struct CapturedRequest {
    content_type: String,
    body: String,
}

async fn provider(State(state): State<ProviderState>, request: AxumRequest) -> impl IntoResponse {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = to_bytes(request.into_body(), 16 * 1024).await.unwrap();
    state.requests.lock().unwrap().push(CapturedRequest {
        content_type,
        body: String::from_utf8(body.to_vec()).unwrap(),
    });
    (
        state.status,
        [(header::CONTENT_TYPE, "application/json")],
        state.body,
    )
}

async fn fake_provider(
    status: StatusCode,
    body: &'static str,
) -> (String, Arc<Mutex<Vec<CapturedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = ProviderState {
        requests: requests.clone(),
        status,
        body,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/verify", post(provider))
        .with_state(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}/verify"), requests)
}

fn app(configure: impl FnOnce(&mut AuthConfig)) -> Router {
    let mut config = AuthConfig::new([141_u8; 32]).unwrap();
    configure(&mut config);
    lucid_auth::axum::router(Arc::new(AuthService::new(
        Arc::new(MemoryStore::default()),
        config,
    )))
}

fn captcha_request(path: &str) -> Request<Body> {
    Request::post(path)
        .header("x-captcha-response", "token +&")
        .header("x-forwarded-for", "203.0.113.9")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

fn with_url(config: &mut CaptchaConfig, url: &str) {
    match config {
        CaptchaConfig::CloudflareTurnstile(options) => {
            options.site_verify_url_override = Some(url.into())
        }
        CaptchaConfig::GoogleRecaptcha(options) => {
            options.site_verify_url_override = Some(url.into())
        }
        CaptchaConfig::HCaptcha(options) => options.site_verify_url_override = Some(url.into()),
        CaptchaConfig::CaptchaFox(options) => options.site_verify_url_override = Some(url.into()),
    }
}

async fn response_body(response: axum::response::Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn default_and_replacement_paths_return_exact_missing_response() {
    let application = app(|config| {
        config
            .add_plugin(CaptchaPlugin::new(CaptchaConfig::CloudflareTurnstile(
                CloudflareTurnstileOptions::new("secret"),
            )))
            .unwrap();
    });
    for path in [
        "/api/auth/sign-up/email",
        "/api/auth/sign-in//email/",
        "/api/auth/request-password-reset?next=ignored",
    ] {
        let response = application
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain;charset=UTF-8"
        );
        assert_eq!(
            response_body(response).await,
            r#"{"message":"Missing CAPTCHA response","code":"MISSING_RESPONSE"}"#
        );
    }
    assert_ne!(
        application
            .oneshot(
                Request::get("/api/auth/get-session")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let replacement = app(|config| {
        let mut options = HCaptchaOptions::new("secret");
        options.endpoints = Some(vec!["/sign-in/**".into()]);
        config
            .add_plugin(CaptchaPlugin::new(CaptchaConfig::HCaptcha(options)))
            .unwrap();
    });
    assert_eq!(
        replacement
            .clone()
            .oneshot(
                Request::get("/api/auth/sign-in/social/google")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_ne!(
        replacement
            .oneshot(
                Request::get("/api/auth/sign-up/email")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn all_provider_wire_encodings_are_exact() {
    let cases = [
        (
            CaptchaConfig::CloudflareTurnstile(CloudflareTurnstileOptions::new("secret +&")),
            "application/json",
            r#"{"secret":"secret +&","response":"token +&","remoteip":"203.0.113.9"}"#,
        ),
        (
            CaptchaConfig::GoogleRecaptcha(GoogleRecaptchaOptions::new("secret +&")),
            "application/x-www-form-urlencoded",
            "secret=secret+%2B%26&response=token+%2B%26&remoteip=203.0.113.9",
        ),
        (
            CaptchaConfig::HCaptcha({
                let mut o = HCaptchaOptions::new("secret +&");
                o.site_key = Some("site +&".into());
                o
            }),
            "application/x-www-form-urlencoded",
            "secret=secret+%2B%26&response=token+%2B%26&sitekey=site+%2B%26&remoteip=203.0.113.9",
        ),
        (
            CaptchaConfig::CaptchaFox({
                let mut o = CaptchaFoxOptions::new("secret +&");
                o.site_key = Some("site +&".into());
                o
            }),
            "application/x-www-form-urlencoded",
            "secret=secret+%2B%26&response=token+%2B%26&sitekey=site+%2B%26&remoteIp=203.0.113.9",
        ),
    ];
    for (mut captcha, content_type, expected_body) in cases {
        let (url, requests) = fake_provider(StatusCode::OK, r#"{"success":true}"#).await;
        with_url(&mut captcha, &url);
        let application = app(|config| config.add_plugin(CaptchaPlugin::new(captcha)).unwrap());
        let response = application
            .oneshot(captcha_request("/api/auth/sign-in/email"))
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].content_type, content_type);
        assert_eq!(requests[0].body, expected_body);
    }
}

#[tokio::test]
async fn rejection_outage_and_rate_limit_fail_closed_in_order() {
    let (url, requests) = fake_provider(StatusCode::OK, r#"{"success":false}"#).await;
    let application = app(|config| {
        config.rate_limit.enabled = true;
        config
            .rate_limit
            .custom_rules
            .push(RateLimitCustomRule::limit("/sign-in/email", 60, 1));
        let mut options = CaptchaFoxOptions::new("secret");
        options.site_verify_url_override = Some(url);
        config
            .add_plugin(CaptchaPlugin::new(CaptchaConfig::CaptchaFox(options)))
            .unwrap();
    });
    let first = application
        .clone()
        .oneshot(captcha_request("/api/auth/sign-in/email"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_body(first).await,
        r#"{"message":"Captcha verification failed","code":"VERIFICATION_FAILED"}"#
    );
    let second = application
        .oneshot(captcha_request("/api/auth/sign-in/email"))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(requests.lock().unwrap().len(), 1);

    let (url, _) = fake_provider(StatusCode::BAD_GATEWAY, "{}").await;
    let outage = app(|config| {
        let mut options = HCaptchaOptions::new("secret");
        options.site_verify_url_override = Some(url);
        config
            .add_plugin(CaptchaPlugin::new(CaptchaConfig::HCaptcha(options)))
            .unwrap();
    })
    .oneshot(captcha_request("/api/auth/sign-in/email"))
    .await
    .unwrap();
    assert_eq!(outage.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_body(outage).await,
        r#"{"message":"Something went wrong","code":"UNKNOWN_ERROR"}"#
    );
}

#[tokio::test]
async fn protected_preflight_runs_after_rate_limit_and_captcha() {
    let application = app(|config| {
        config.set_base_url("https://auth.example.test").unwrap();
        config.trust_origin("https://app.example.test").unwrap();
        config.enable_cors();
        config
            .add_plugin(CaptchaPlugin::new(CaptchaConfig::CloudflareTurnstile(
                CloudflareTurnstileOptions::new("secret"),
            )))
            .unwrap();
    });
    let response = application
        .oneshot(
            Request::options("/api/auth/sign-in/email")
                .header(header::ORIGIN, "https://app.example.test")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_body(response).await,
        r#"{"message":"Missing CAPTCHA response","code":"MISSING_RESPONSE"}"#
    );
}

#[tokio::test]
async fn disabled_ip_tracking_ignores_the_legacy_remote_ip_header() {
    let (url, requests) = fake_provider(StatusCode::OK, r#"{"success":true}"#).await;
    let application = app(|config| {
        config.ip_address.disable_ip_tracking = true;
        let mut options = CaptchaFoxOptions::new("secret");
        options.site_verify_url_override = Some(url);
        config
            .add_plugin(CaptchaPlugin::new(CaptchaConfig::CaptchaFox(options)))
            .unwrap();
    });
    let request = Request::post("/api/auth/sign-in/email")
        .header("x-captcha-response", "token")
        .header("x-captcha-user-remote-ip", "198.51.100.44")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    application.oneshot(request).await.unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, "secret=secret&response=token");
}

#[tokio::test]
async fn malformed_and_falsey_provider_responses_follow_better_fetch() {
    for (provider_body, expected) in [
        ("{}", StatusCode::FORBIDDEN),
        ("not-json", StatusCode::FORBIDDEN),
        ("", StatusCode::INTERNAL_SERVER_ERROR),
        ("null", StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let (url, _) = fake_provider(StatusCode::OK, provider_body).await;
        let application = app(|config| {
            let mut options = HCaptchaOptions::new("secret");
            options.site_verify_url_override = Some(url);
            config
                .add_plugin(CaptchaPlugin::new(CaptchaConfig::HCaptcha(options)))
                .unwrap();
        });
        let response = application
            .oneshot(captcha_request("/api/auth/sign-in/email"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            expected,
            "provider body {provider_body:?}"
        );
    }
}
