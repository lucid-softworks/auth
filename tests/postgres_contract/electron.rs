use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt as _;
use lucid_auth::{ElectronPlugin, TestUtilsPlugin};
use serde_json::{Value, json};
use tower::ServiceExt as _;

pub(super) async fn assert_round_trip(
    pool: &sqlx::PgPool,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(PostgresStore::new(pool.clone(), Default::default()));
    let mut config = AuthConfig::new([78; 32])?;
    config.set_base_url("http://localhost:3000")?;
    config.trust_origin("http://localhost:3000")?;
    config.add_plugin(ElectronPlugin::default())?;
    config.add_plugin(TestUtilsPlugin::default())?;
    let service = Arc::new(AuthService::new(store.clone(), config));
    assert_no_schema(&service, pool).await?;

    let auth_headers = service.test().unwrap().get_auth_headers(user_id).await?;
    let cookie = auth_headers.get("cookie").unwrap();
    let app = lucid_auth::axum::router(service.clone());
    let code = authenticated_transfer(&app, cookie).await?;
    assert!(
        service
            .find_verification_value(&format!("electron:{code}"))
            .await?
            .is_some()
    );
    assert_atomic_exchange(app, &code).await?;
    Ok(())
}

async fn assert_no_schema(
    service: &AuthService,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(service.plugin_migrations().is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name LIKE '%electron%'",
        )
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

async fn authenticated_transfer(
    app: &axum::Router,
    cookie: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post(
                "/api/auth/electron/transfer-user?client_id=electron&state=postgres&code_challenge=Ue4-bylfXJrFw0GSSrFNH1mZ1CzWZReNHOKAzmVyJmA",
            )
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, "http://localhost:3000")
            .body(Body::from(
                r#"{"callbackURL":"http://localhost:3000/auth/callback"}"#,
            ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(body["url"], "http://localhost:3000/auth/callback");
    Ok(body["electron_authorization_code"]
        .as_str()
        .unwrap()
        .to_owned())
}

async fn assert_atomic_exchange(
    app: axum::Router,
    code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (left, right) = tokio::join!(
        app.clone().oneshot(exchange_request(code)),
        app.clone().oneshot(exchange_request(code))
    );
    let statuses = [left?.status(), right?.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::NOT_FOUND)
            .count(),
        1
    );
    Ok(())
}

fn exchange_request(code: &str) -> Request<Body> {
    Request::post("/api/auth/electron/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "token": code,
                "state": "postgres",
                "code_verifier": "postgres-verifier"
            })
            .to_string(),
        ))
        .unwrap()
}
