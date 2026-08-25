use super::support::{fixture, get, post};
use axum::http::{StatusCode, header};
use serde_json::{Value, json};

fn assert_json(status: StatusCode, headers: &axum::http::HeaderMap) {
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn missing_projected_fields_are_undefined_instead_of_null() {
    let fixture = fixture(None).await;
    for operation in ["features", "seat_balances", "set_all_seats"] {
        fixture.client.respond(operation, json!({})).await;
    }

    let (status, headers, body) = get(&fixture, "/api/auth/commet/features").await;
    assert_json(status, &headers);
    assert!(body.is_empty());

    let (status, headers, body) = get(&fixture, "/api/auth/commet/seats").await;
    assert_json(status, &headers);
    assert!(body.is_empty());

    let (status, headers, body) = post(
        &fixture,
        "/api/auth/commet/seats/set-all",
        json!({"seats": {"members": 1}}),
    )
    .await;
    assert_json(status, &headers);
    assert!(body.is_empty());
}

#[tokio::test]
async fn missing_portal_url_is_omitted_from_the_json_object() {
    let fixture = fixture(None).await;
    fixture.client.respond("portal", json!({})).await;

    let (status, headers, body) = get(&fixture, "/api/auth/commet/portal").await;
    assert_json(status, &headers);
    assert_eq!(body.as_ref(), br#"{"redirect":true}"#);
}

#[tokio::test]
async fn portal_url_is_not_response_validated_without_a_return_url() {
    let fixture = fixture(None).await;
    for portal_url in [Value::Null, json!(7), json!({"nested": true})] {
        fixture
            .client
            .respond("portal", json!({"portalUrl": portal_url.clone()}))
            .await;
        let (status, _, body) = get(&fixture, "/api/auth/commet/portal").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"url": portal_url, "redirect": true})
        );
    }
}

#[tokio::test]
async fn configured_return_url_still_exposes_missing_portal_url_as_a_failure() {
    let fixture = fixture(Some("https://app.example.test/billing")).await;
    fixture.client.respond("portal", json!({})).await;

    let (status, _, body) = get(&fixture, "/api/auth/commet/portal").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"message": "Failed to access customer portal"})
    );
}

#[tokio::test]
async fn missing_subscription_id_is_coerced_to_undefined_for_the_provider() {
    let fixture = fixture(None).await;
    fixture.client.respond("subscription", json!({})).await;

    let (status, _, body) = post(&fixture, "/api/auth/commet/subscription/cancel", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"id": "undefined"})
    );
    assert_eq!(fixture.client.cancellation_ids().await, ["undefined"]);
}

#[tokio::test]
async fn subscription_presence_uses_javascript_truthiness() {
    let fixture = fixture(None).await;
    for inactive in [json!(null), json!(false), json!(0), json!("")] {
        fixture.client.respond("subscription", inactive).await;
        let (status, _, body) =
            post(&fixture, "/api/auth/commet/subscription/cancel", json!({})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"message": "No active subscription found"})
        );
    }
    assert!(fixture.client.cancellation_ids().await.is_empty());
}
