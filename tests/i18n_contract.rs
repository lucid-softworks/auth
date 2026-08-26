use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, AuthSession, AuthUser, AxumPluginRoute, I18nConfig,
    I18nLocaleContext, I18nLocaleDetection, I18nLocaleResolver, I18nLocales, I18nPlugin,
    MemoryStore, PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginRequestContext,
    SessionWithUser,
};
use serde_json::{Value, json};
use std::{borrow::Cow, collections::BTreeMap, sync::Arc};
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct PreservedExtension;

#[derive(Debug)]
struct FixturePlugin;

#[async_trait]
impl AuthPlugin for FixturePlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "i18n-fixture",
            display_name: "i18n fixture",
            version: "1.7.1",
            provenance: lucid_auth::PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(vec![
                PluginEndpoint {
                    method: PluginHttpMethod::Get,
                    path: Cow::Borrowed("/i18n-api-error"),
                    client_method: "i18nApiError",
                },
                PluginEndpoint {
                    method: PluginHttpMethod::Get,
                    path: Cow::Borrowed("/i18n-json-error"),
                    client_method: "i18nJsonError",
                },
            ]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        vec![
            AxumPluginRoute::new("/i18n-api-error", get(marked_error)),
            AxumPluginRoute::new("/i18n-json-error", get(unmarked_error)),
        ]
    }
}

async fn marked_error() -> Response {
    let mut response = lucid_auth::axum::api_error_with_body(
        StatusCode::IM_A_TEAPOT,
        json!({
            "code": "CUSTOM_ERROR",
            "message": "Original custom message",
            "discarded": "not carried into the translated APIError"
        }),
    );
    response.headers_mut().insert(
        "x-error-context",
        "preserved".parse().expect("static header is valid"),
    );
    response.extensions_mut().insert(PreservedExtension);
    response
}

async fn unmarked_error() -> Response {
    (
        StatusCode::IM_A_TEAPOT,
        axum::Json(json!({
            "code": "CUSTOM_ERROR",
            "message": "Not an APIError"
        })),
    )
        .into_response()
}

fn dictionary(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(code, message)| ((*code).into(), (*message).into()))
        .collect()
}

fn plugin() -> I18nPlugin {
    let translations = BTreeMap::from([
        (
            "en".into(),
            dictionary(&[
                ("INVALID_EMAIL_OR_PASSWORD", "English replacement"),
                ("CUSTOM_ERROR", "English custom"),
            ]),
        ),
        (
            "fr".into(),
            dictionary(&[
                (
                    "INVALID_EMAIL_OR_PASSWORD",
                    "Email ou mot de passe invalide",
                ),
                ("CUSTOM_ERROR", "Erreur personnalisée"),
                ("EMPTY", ""),
            ]),
        ),
    ]);
    I18nPlugin::new(I18nConfig::new(translations).unwrap()).unwrap()
}

fn application(configure: impl FnOnce(&mut AuthConfig)) -> Router {
    let mut config = AuthConfig::new([142_u8; 32]).unwrap();
    configure(&mut config);
    lucid_auth::axum::router(Arc::new(AuthService::new(
        Arc::new(MemoryStore::default()),
        config,
    )))
}

async fn body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn core_and_custom_api_errors_translate_but_arbitrary_json_does_not() {
    let app = application(|config| {
        config.email_and_password.enabled = true;
        config.add_plugin(FixturePlugin).unwrap();
        config.add_plugin(plugin()).unwrap();
    });
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/email")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT_LANGUAGE, "fr-CA")
                .body(Body::from(
                    json!({"email":"missing@example.com","password":"password"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body(response).await,
        json!({
            "code": "INVALID_EMAIL_OR_PASSWORD",
            "message": "Email ou mot de passe invalide",
            "originalMessage": "Invalid email or password"
        })
    );

    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/i18n-api-error")
                .header(header::ACCEPT_LANGUAGE, "fr")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(response.headers()["x-error-context"], "preserved");
    assert!(response.extensions().get::<PreservedExtension>().is_some());
    assert_eq!(
        body(response).await,
        json!({
            "code": "CUSTOM_ERROR",
            "message": "Erreur personnalisée",
            "originalMessage": "Original custom message"
        })
    );

    let response = app
        .oneshot(
            Request::get("/api/auth/i18n-json-error")
                .header(header::ACCEPT_LANGUAGE, "fr")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(
        body(response).await,
        json!({"code":"CUSTOM_ERROR","message":"Not an APIError"})
    );
}

#[tokio::test]
async fn missing_or_empty_selected_entries_never_retry_the_default_catalog() {
    for french in [None, Some("")] {
        let translations = BTreeMap::from([
            (
                "en".into(),
                dictionary(&[("CUSTOM_ERROR", "must not be selected")]),
            ),
            (
                "fr".into(),
                french
                    .map(|translation| dictionary(&[("CUSTOM_ERROR", translation)]))
                    .unwrap_or_default(),
            ),
        ]);
        let i18n = I18nPlugin::new(I18nConfig::new(translations).unwrap()).unwrap();
        let app = application(|config| {
            config.add_plugin(FixturePlugin).unwrap();
            config.add_plugin(i18n).unwrap();
        });
        let response = app
            .oneshot(
                Request::get("/api/auth/i18n-api-error")
                    .header(header::ACCEPT_LANGUAGE, "fr")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            body(response).await,
            json!({
                "code": "CUSTOM_ERROR",
                "message": "Original custom message",
                "discarded": "not carried into the translated APIError"
            })
        );
    }
}

#[tokio::test]
async fn ordered_detection_exact_matching_and_default_limitations_match() {
    let mut config = plugin().config().clone();
    config.detection = vec![I18nLocaleDetection::Cookie, I18nLocaleDetection::Header];
    config.locale_cookie = "language".into();
    let plugin = I18nPlugin::new(config).unwrap();
    let request = PluginRequestContext {
        method: "POST".into(),
        path: "/fixture".into(),
        query: None,
        headers: BTreeMap::from([
            ("accept-language".into(), "fr-CA;q=0.9,en;q=0.1".into()),
            ("cookie".into(), "language=en; language=fr".into()),
        ]),
    };
    assert_eq!(
        plugin
            .detect_locale(I18nLocaleContext {
                request: Some(request),
                session: None,
            })
            .await,
        "fr"
    );

    let mut config = plugin.config().clone();
    config.detection.clear();
    config.default_locale = "missing".into();
    let plugin = I18nPlugin::new(config).unwrap();
    assert_eq!(
        plugin
            .detect_locale(I18nLocaleContext {
                request: None,
                session: None,
            })
            .await,
        "missing"
    );
}

struct AsyncLocale;

#[async_trait]
impl I18nLocaleResolver for AsyncLocale {
    async fn get_locale(&self, context: I18nLocaleContext) -> Option<String> {
        assert!(context.request.is_none());
        Some("fr".into())
    }
}

#[tokio::test]
async fn session_and_async_callback_detection_use_the_exact_user_projection() {
    let mut config = plugin().config().clone();
    config.detection = vec![I18nLocaleDetection::Session];
    config.user_locale_field = "language".into();
    let plugin = I18nPlugin::new(config).unwrap();
    let now = Utc::now();
    let session = SessionWithUser {
        session: AuthSession {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token: "token".into(),
            actor_user_id: None,
            authentication_method: Some(lucid_auth::AuthenticationMethod::Password),
            expires_at: now,
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
            additional_fields: Default::default(),
        },
        user: AuthUser {
            id: Uuid::new_v4(),
            username: None,
            display_username: None,
            name: "Locale User".into(),
            email: "locale@example.com".into(),
            email_verified: true,
            image: None,
            additional_fields: serde_json::Map::from_iter([(
                "language".into(),
                Value::String("fr".into()),
            )]),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        },
    };
    assert_eq!(
        plugin
            .detect_locale(I18nLocaleContext {
                request: None,
                session: Some(session),
            })
            .await,
        "fr"
    );

    let mut config = plugin.config().clone();
    config.detection = vec![I18nLocaleDetection::Callback];
    config.get_locale = Some(Arc::new(AsyncLocale));
    let plugin = I18nPlugin::new(config).unwrap();
    assert_eq!(
        plugin
            .detect_locale(I18nLocaleContext {
                request: None,
                session: None,
            })
            .await,
        "fr"
    );
}

#[test]
fn pinned_catalog_surface_is_complete() {
    let expected = [
        "ar", "bn", "de", "en", "es", "fa", "fr", "hi", "id", "it", "ja", "ko", "nl", "pl", "pt",
        "ru", "sv", "th", "tr", "uk", "vi", "zh",
    ];
    assert_eq!(
        I18nLocales::all()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected
    );
    assert!(
        I18nLocales::all()
            .values()
            .all(|catalog| catalog.len() == 34)
    );
}
