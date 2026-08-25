use crate::support::{fixture, send, send_bytes};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};

#[tokio::test]
async fn webhook_preserves_raw_body_and_maps_signature_failures() {
    let fixture = fixture(None).await;
    let raw = b" {\"callbackURL\":\"https://untrusted.example\",\"raw\":true}\n";
    let accepted = send_bytes(
        &fixture.app,
        Request::post("/api/auth/stripe/webhook")
            .header("stripe-signature", "t=1,v1=exact")
            .body(Body::from(raw.as_slice()))
            .unwrap(),
    )
    .await;
    assert_eq!(accepted.0, StatusCode::OK);
    assert_eq!(accepted.2, br#"{"success":true}"#);
    assert_eq!(
        fixture.client.webhook_request().await,
        Some((raw.to_vec(), "t=1,v1=exact".into(), "whsec_contract".into()))
    );

    let rejected = send(
        &fixture.app,
        Request::post("/api/auth/stripe/webhook")
            .header("stripe-signature", "bad")
            .body(Body::from("raw-not-json"))
            .unwrap(),
    )
    .await;
    assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
    assert_eq!(rejected.2["code"], "FAILED_TO_CONSTRUCT_STRIPE_EVENT");
}
