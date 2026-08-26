use super::support::{CommetCall, fixture, get, post, post_absent, post_with_content_type};
use axum::http::StatusCode;
use lucid_auth::{
    CommetFeature, CommetPortalOptions, CommetSeatMutation, CommetSeatSetAll,
    CommetSubscriptionsOptions, CommetUsageEvent,
};
use serde_json::{Map, Value, json};

fn features() -> Vec<CommetFeature> {
    vec![
        CommetFeature::Portal(CommetPortalOptions::default()),
        CommetFeature::Subscriptions(CommetSubscriptionsOptions::default()),
        CommetFeature::Features,
        CommetFeature::Usage,
        CommetFeature::Seats,
    ]
}

#[tokio::test]
async fn body_validation_runs_before_session_and_session_errors_are_generic() {
    let fixture = fixture(features(), false).await;
    assert_eq!(
        post_absent(&fixture, "/api/auth/commet/usage/track").await,
        (
            StatusCode::BAD_REQUEST,
            json!({
                "code": "VALIDATION_ERROR",
                "message": "[body] Invalid input: expected object, received undefined"
            })
        )
    );
    assert_eq!(
        post(
            &fixture,
            "/api/auth/commet/seats/add",
            json!({"featureCode": "members", "count": 0}),
        )
        .await,
        (
            StatusCode::BAD_REQUEST,
            json!({
                "code": "VALIDATION_ERROR",
                "message": "[body.count] Too small: expected number to be >=1"
            })
        )
    );
    assert_eq!(
        post(
            &fixture,
            "/api/auth/commet/subscription/cancel",
            serde_json::Value::Null,
        )
        .await,
        (
            StatusCode::BAD_REQUEST,
            json!({
                "code": "VALIDATION_ERROR",
                "message": "[body] Invalid input: expected object, received null"
            })
        )
    );
    assert_eq!(
        get(&fixture, "/api/auth/commet/features").await,
        (
            StatusCode::UNAUTHORIZED,
            json!({"code": "UNAUTHORIZED", "message": "Unauthorized"})
        )
    );
}

#[tokio::test]
async fn empty_strings_fractional_counts_and_unconstrained_set_all_values_are_accepted() {
    let fixture = fixture(features(), true).await;
    for (path, body) in [
        (
            "/api/auth/commet/seats/add",
            json!({"featureCode": "", "count": 1.25, "unknown": true}),
        ),
        (
            "/api/auth/commet/seats/set-all",
            json!({"seats": {"negative": -5, "zero": 0, "fractional": 0.25}, "unknown": true}),
        ),
    ] {
        assert_eq!(post(&fixture, path, body).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn validation_aggregates_every_schema_issue_in_declaration_order() {
    let fixture = fixture(features(), false).await;
    for (path, body, message) in [
        (
            "/api/auth/commet/seats/add",
            json!({}),
            "[body.featureCode] Invalid input: expected string, received undefined; [body.count] Invalid input: expected number, received undefined",
        ),
        (
            "/api/auth/commet/usage/track",
            json!({"properties": 1}),
            "[body.feature] Invalid input: expected string, received undefined; [body.properties] Invalid input: expected record, received number",
        ),
        (
            "/api/auth/commet/subscription/cancel",
            json!({"reason": 1, "immediate": "bad"}),
            "[body.reason] Invalid input: expected string, received number; [body.immediate] Invalid input: expected boolean, received string",
        ),
        (
            "/api/auth/commet/seats/set-all",
            json!({"seats": {"first": "bad", "second": false}}),
            "[body.seats.first] Invalid input: expected number, received string; [body.seats.second] Invalid input: expected number, received boolean",
        ),
    ] {
        assert_eq!(
            post(&fixture, path, body).await,
            (
                StatusCode::BAD_REQUEST,
                json!({"code": "VALIDATION_ERROR", "message": message})
            )
        );
    }
}

#[tokio::test]
async fn unsupported_content_types_use_better_call_coded_errors_before_validation() {
    let fixture = fixture(features(), false).await;
    for body in ["", "{}"] {
        assert_eq!(
            post_with_content_type(&fixture, "/api/auth/commet/usage/track", "text/plain", body,)
                .await,
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                json!({
                    "code": "UNSUPPORTED_MEDIA_TYPE",
                    "message": "Content-Type \"text/plain\" is not allowed. Allowed types: application/json"
                })
            )
        );
    }
}

#[tokio::test]
async fn numbers_are_rounded_through_javascript_f64_semantics() {
    let fixture = fixture(features(), true).await;
    let user_id = fixture.user_id.clone().unwrap();
    for (path, body) in [
        (
            "/api/auth/commet/usage/track",
            json!({"feature": "reports", "value": 9_007_199_254_740_993_u64}),
        ),
        (
            "/api/auth/commet/seats/add",
            json!({"featureCode": "members", "count": 9_007_199_254_740_993_u64}),
        ),
        (
            "/api/auth/commet/seats/set-all",
            json!({"seats": {"members": 9_007_199_254_740_993_u64}}),
        ),
    ] {
        assert_eq!(post(&fixture, path, body).await.0, StatusCode::OK);
    }

    let rounded = serde_json::Number::from(9_007_199_254_740_992_u64);
    assert_eq!(
        fixture.client.calls().await,
        vec![
            CommetCall::TrackUsage(
                CommetUsageEvent {
                    feature_code: "reports".into(),
                    customer_id: user_id.clone(),
                    value: Some(rounded.clone()),
                    properties: None,
                },
                None,
            ),
            CommetCall::AddSeats(CommetSeatMutation {
                customer_id: user_id.clone(),
                feature_code: "members".into(),
                count: rounded.clone(),
            }),
            CommetCall::SetAllSeats(CommetSeatSetAll {
                customer_id: user_id,
                seats: Map::from_iter([("members".into(), Value::Number(rounded))]),
            }),
        ]
    );
}

#[tokio::test]
async fn json_numbers_that_javascript_parses_as_infinity_fail_zod_number_validation() {
    let fixture = fixture(features(), false).await;
    for (path, body, message) in [
        (
            "/api/auth/commet/usage/track",
            r#"{"feature":"reports","value":1e400}"#,
            "[body.value] Invalid input: expected number, received number",
        ),
        (
            "/api/auth/commet/seats/add",
            r#"{"featureCode":"members","count":1e400}"#,
            "[body.count] Invalid input: expected number, received number",
        ),
        (
            "/api/auth/commet/seats/set-all",
            r#"{"seats":{"members":1e400}}"#,
            "[body.seats.members] Invalid input: expected number, received number",
        ),
    ] {
        assert_eq!(
            post_with_content_type(&fixture, path, "application/json", body).await,
            (
                StatusCode::BAD_REQUEST,
                json!({"code": "VALIDATION_ERROR", "message": message})
            )
        );
    }
}
