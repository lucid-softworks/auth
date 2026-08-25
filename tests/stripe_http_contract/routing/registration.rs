use crate::support::{disabled_app, fixture, send};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};

#[tokio::test]
async fn routes_are_registered_with_exact_methods_and_subscription_condition() {
    let disabled = disabled_app();
    assert_eq!(
        send(
            &disabled,
            Request::get("/api/auth/subscription/success")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let missing_signature = send(
        &disabled,
        Request::post("/api/auth/stripe/webhook")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(missing_signature.0, StatusCode::BAD_REQUEST);
    assert_eq!(missing_signature.2["code"], "STRIPE_SIGNATURE_NOT_FOUND");

    let fixture = fixture(None).await;
    for path in [
        "/api/auth/subscription/upgrade",
        "/api/auth/subscription/cancel",
        "/api/auth/subscription/restore",
        "/api/auth/subscription/billing-portal",
    ] {
        let response = send(
            &fixture.app,
            Request::get(path).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.0, StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }
    for path in [
        "/api/auth/subscription/list",
        "/api/auth/subscription/success",
    ] {
        let response = send(
            &fixture.app,
            Request::post(path).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.0, StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }
}
