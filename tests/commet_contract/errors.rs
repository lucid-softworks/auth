use super::support::{fixture, get, post, post_absent};
use axum::http::StatusCode;
use lucid_auth::{
    CommetFeature, CommetPortalOptions, CommetProviderError, CommetSubscriptionsOptions,
    PluginApiError,
};
use serde_json::{Value, json};

fn features() -> Vec<CommetFeature> {
    vec![
        CommetFeature::Portal(CommetPortalOptions::default()),
        CommetFeature::Subscriptions(CommetSubscriptionsOptions::default()),
        CommetFeature::Features,
        CommetFeature::Usage,
        CommetFeature::Seats,
    ]
}

enum Request {
    Get(&'static str),
    Post(&'static str, Value),
}

#[tokio::test]
async fn customer_and_feature_routes_use_their_pinned_failure_messages() {
    assert_failures(vec![
        (
            "portal",
            Request::Get("/api/auth/commet/portal"),
            "Failed to access customer portal",
        ),
        (
            "subscription",
            Request::Get("/api/auth/commet/subscription"),
            "Failed to retrieve subscription",
        ),
        (
            "cancel",
            Request::Post("/api/auth/commet/subscription/cancel", json!({})),
            "Failed to cancel subscription",
        ),
        (
            "list_features",
            Request::Get("/api/auth/commet/features"),
            "Failed to list features",
        ),
        (
            "get_feature",
            Request::Get("/api/auth/commet/features/reports"),
            "Failed to get feature",
        ),
        (
            "check_usage",
            Request::Get("/api/auth/commet/features/reports/check"),
            "Failed to check feature",
        ),
        (
            "check_usage",
            Request::Get("/api/auth/commet/features/reports/can-use"),
            "Failed to check feature usage",
        ),
    ])
    .await;
}

#[tokio::test]
async fn usage_and_seat_routes_use_their_pinned_failure_messages() {
    assert_failures(vec![
        (
            "track_usage",
            Request::Post(
                "/api/auth/commet/usage/track",
                json!({"feature": "reports"}),
            ),
            "Failed to track usage",
        ),
        (
            "list_seats",
            Request::Get("/api/auth/commet/seats"),
            "Failed to list seats",
        ),
        (
            "add_seats",
            Request::Post(
                "/api/auth/commet/seats/add",
                json!({"featureCode": "members", "count": 1}),
            ),
            "Failed to add seats",
        ),
        (
            "remove_seats",
            Request::Post(
                "/api/auth/commet/seats/remove",
                json!({"featureCode": "members", "count": 1}),
            ),
            "Failed to remove seats",
        ),
        (
            "set_seats",
            Request::Post(
                "/api/auth/commet/seats/set",
                json!({"featureCode": "members", "count": 1}),
            ),
            "Failed to set seats",
        ),
        (
            "set_all_seats",
            Request::Post(
                "/api/auth/commet/seats/set-all",
                json!({"seats": {"members": 1}}),
            ),
            "Failed to set all seats",
        ),
    ])
    .await;
}

async fn assert_failures(cases: Vec<(&'static str, Request, &'static str)>) {
    for (operation, request, message) in cases {
        let fixture = fixture(features(), true).await;
        fixture
            .client
            .fail(
                operation,
                CommetProviderError::new("sensitive provider detail"),
            )
            .await;
        let response = match request {
            Request::Get(path) => get(&fixture, path).await,
            Request::Post(path, body) => post(&fixture, path, body).await,
        };
        assert_eq!(
            response,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"message": message})
            )
        );
    }
}

#[tokio::test]
async fn provider_api_errors_are_preserved_and_ordinary_failures_are_masked() {
    let fixture = fixture(features(), true).await;
    fixture
        .client
        .fail(
            "portal",
            CommetProviderError::api(PluginApiError::new(
                400,
                "BAD_REQUEST",
                "provider API error",
            )),
        )
        .await;
    assert_eq!(
        get(&fixture, "/api/auth/commet/portal").await,
        (
            StatusCode::BAD_REQUEST,
            json!({"message": "provider API error"})
        )
    );

    fixture
        .client
        .fail(
            "list_features",
            CommetProviderError::new("secret provider detail"),
        )
        .await;
    assert_eq!(
        get(&fixture, "/api/auth/commet/features").await,
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"message": "Failed to list features"})
        )
    );
}

#[tokio::test]
async fn cancellation_without_an_active_subscription_is_a_bad_request() {
    let fixture = fixture(features(), true).await;
    fixture.client.respond("subscription", Value::Null).await;
    assert_eq!(
        post_absent(&fixture, "/api/auth/commet/subscription/cancel").await,
        (
            StatusCode::BAD_REQUEST,
            json!({"message": "No active subscription found"})
        )
    );
}
