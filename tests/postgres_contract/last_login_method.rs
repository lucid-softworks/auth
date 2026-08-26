use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{AuthService, AuthStore, postgres::PostgresStore};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

pub(crate) async fn assert_http_round_trip(
    service: &Arc<AuthService>,
    store: &PostgresStore,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = lucid_auth::axum::router(service.clone())
        .oneshot(
            Request::post("/api/auth/sign-in/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "owner@example.com",
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|cookie| cookie.starts_with("better-auth.last_used_login_method=email;"))
    );

    let stored = store.find_user_by_id(user_id).await?.unwrap();
    assert_eq!(stored.additional_fields["lastLoginMethod"], "email");
    Ok(())
}
