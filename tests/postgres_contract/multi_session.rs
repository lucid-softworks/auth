use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::AuthService;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

pub(crate) async fn assert_http_round_trip(
    service: &Arc<AuthService>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = lucid_auth::axum::router(service.clone());
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "username": "owner",
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cookies.contains("_multi-"));

    let response = app
        .oneshot(
            Request::get("/api/auth/multi-session/list-device-sessions")
                .header(header::COOKIE, cookies)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(body.as_array().map(Vec::len), Some(1));
    Ok(())
}
