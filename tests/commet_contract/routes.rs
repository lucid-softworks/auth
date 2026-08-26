use super::support::{CommetCall, fixture, get, post, post_absent};
use axum::http::StatusCode;
use lucid_auth::{
    CommetFeature, CommetPortalOptions, CommetSeatMutation, CommetSeatSetAll,
    CommetSubscriptionCancel, CommetSubscriptionsOptions, CommetUsageEvent, CommetUsageProperty,
};
use serde_json::{Map, Value, json};

const PORTAL_URL: &str = concat!("https:", "/", "/portal.commet.test/session?keep=1");

fn all_features(return_url: Option<&str>) -> Vec<CommetFeature> {
    vec![
        CommetFeature::Portal(CommetPortalOptions {
            return_url: return_url.map(str::to_owned),
        }),
        CommetFeature::Subscriptions(CommetSubscriptionsOptions::default()),
        CommetFeature::Features,
        CommetFeature::Usage,
        CommetFeature::Seats,
    ]
}

#[tokio::test]
async fn portal_subscription_and_feature_routes_translate_and_project() {
    let fixture = fixture(all_features(None), true).await;
    let user_id = fixture.user_id.clone().unwrap();
    assert_eq!(
        get(&fixture, "/api/auth/commet/portal").await,
        (StatusCode::OK, json!({"url": PORTAL_URL, "redirect": true}))
    );
    assert_eq!(
        get(&fixture, "/api/auth/commet/subscription").await,
        (
            StatusCode::OK,
            json!({"id": "sub_contract", "status": "active"})
        )
    );
    assert_eq!(
        post_absent(&fixture, "/api/auth/commet/subscription/cancel").await,
        (
            StatusCode::OK,
            json!({"id": "sub_contract", "status": "canceled"})
        )
    );
    assert_eq!(
        get(&fixture, "/api/auth/commet/features").await,
        (StatusCode::OK, json!([{"code": "reports"}]))
    );
    assert_eq!(
        get(&fixture, "/api/auth/commet/features/reports").await,
        (
            StatusCode::OK,
            json!({"id": "access_contract", "customerId": user_id, "code": "reports"})
        )
    );
    let checked = json!({"allowed": true, "customerId": user_id, "featureCode": "reports"});
    assert_eq!(
        get(&fixture, "/api/auth/commet/features/reports/check").await,
        (StatusCode::OK, checked.clone())
    );
    assert_eq!(
        get(&fixture, "/api/auth/commet/features/reports/can-use").await,
        (StatusCode::OK, checked)
    );
    assert_eq!(
        fixture.client.calls().await,
        vec![
            CommetCall::Portal(user_id.clone()),
            CommetCall::Subscription(user_id.clone()),
            CommetCall::Subscription(user_id.clone()),
            CommetCall::Cancel("sub_contract".into(), CommetSubscriptionCancel::default()),
            CommetCall::ListFeatures(user_id.clone()),
            CommetCall::GetFeature(user_id.clone(), "reports".into()),
            CommetCall::CheckUsage(user_id.clone(), "reports".into()),
            CommetCall::CheckUsage(user_id.clone(), "reports".into()),
        ]
    );
}

#[tokio::test]
async fn usage_route_translates_exact_numbers_and_strips_unknown_fields() {
    let fixture = fixture(all_features(None), true).await;
    let user_id = fixture.user_id.clone().unwrap();
    assert_eq!(
        post(
            &fixture,
            "/api/auth/commet/usage/track",
            json!({"feature": "reports", "value": 2, "unknown": "stripped"}),
        )
        .await,
        (StatusCode::OK, json!({"id": "usage_contract"}))
    );
    assert_eq!(
        fixture.client.calls().await,
        vec![CommetCall::TrackUsage(
            CommetUsageEvent {
                feature_code: "reports".into(),
                customer_id: user_id,
                value: Some(2.into()),
                properties: None,
            },
            None,
        )]
    );
}

#[tokio::test]
async fn all_five_seat_routes_translate_and_project() {
    let fixture = fixture(all_features(None), true).await;
    let user_id = fixture.user_id.clone().unwrap();
    assert_eq!(
        get(&fixture, "/api/auth/commet/seats").await.1,
        json!({"members": 3})
    );
    let cases = [
        (
            "/api/auth/commet/seats/add",
            json!({"featureCode": "members", "count": 1.5}),
            json!({"operation": "add"}),
        ),
        (
            "/api/auth/commet/seats/remove",
            json!({"featureCode": "members", "count": 1}),
            json!({"operation": "remove"}),
        ),
        (
            "/api/auth/commet/seats/set",
            json!({"featureCode": "members", "count": 4}),
            json!({"operation": "set"}),
        ),
        (
            "/api/auth/commet/seats/set-all",
            json!({"seats": {"debt": -2, "fractional": 1.5}}),
            json!([{"operation": "set-all"}]),
        ),
    ];
    for (path, body, expected) in cases {
        assert_eq!(post(&fixture, path, body).await, (StatusCode::OK, expected));
    }
    assert_eq!(fixture.client.calls().await, expected_seat_calls(&user_id));
}

fn expected_seat_calls(user_id: &str) -> Vec<CommetCall> {
    vec![
        CommetCall::ListSeats(user_id.into()),
        CommetCall::AddSeats(CommetSeatMutation {
            customer_id: user_id.into(),
            feature_code: "members".into(),
            count: serde_json::Number::from_f64(1.5).unwrap(),
        }),
        CommetCall::RemoveSeats(CommetSeatMutation {
            customer_id: user_id.into(),
            feature_code: "members".into(),
            count: 1.into(),
        }),
        CommetCall::SetSeats(CommetSeatMutation {
            customer_id: user_id.into(),
            feature_code: "members".into(),
            count: 4.into(),
        }),
        CommetCall::SetAllSeats(CommetSeatSetAll {
            customer_id: user_id.into(),
            seats: Map::from_iter([
                ("debt".into(), Value::from(-2)),
                ("fractional".into(), json!(1.5)),
            ]),
        }),
    ]
}

#[tokio::test]
async fn usage_preserves_js_property_order_and_truthy_idempotency_only() {
    let fixture = fixture(all_features(None), true).await;
    let user_id = fixture.user_id.clone().unwrap();
    let mut properties = Map::new();
    properties.insert("zeta".into(), json!("last-string"));
    properties.insert("10".into(), json!("ten"));
    properties.insert("2".into(), json!("two"));
    properties.insert("alpha".into(), json!("first-string"));
    properties.insert("4294967294".into(), json!("max-index"));
    properties.insert("4294967295".into(), json!("not-index"));

    let mut body = Map::new();
    body.insert("feature".into(), json!(""));
    body.insert("idempotencyKey".into(), json!("caller-key"));
    body.insert("properties".into(), Value::Object(properties));
    body.insert("unknown".into(), json!("stripped"));
    body.insert("value".into(), json!(0));
    assert_eq!(
        post(
            &fixture,
            "/api/auth/commet/usage/track",
            Value::Object(body),
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        post(
            &fixture,
            "/api/auth/commet/usage/track",
            json!({"feature": "reports", "idempotencyKey": ""}),
        )
        .await
        .0,
        StatusCode::OK
    );

    assert_eq!(fixture.client.calls().await, expected_usage_calls(&user_id));
}

fn expected_usage_calls(user_id: &str) -> Vec<CommetCall> {
    vec![
        CommetCall::TrackUsage(
            CommetUsageEvent {
                feature_code: "".into(),
                customer_id: user_id.into(),
                value: Some(0.into()),
                properties: Some(vec![
                    CommetUsageProperty {
                        property: "2".into(),
                        value: "two".into(),
                    },
                    CommetUsageProperty {
                        property: "10".into(),
                        value: "ten".into(),
                    },
                    CommetUsageProperty {
                        property: "4294967294".into(),
                        value: "max-index".into(),
                    },
                    CommetUsageProperty {
                        property: "zeta".into(),
                        value: "last-string".into(),
                    },
                    CommetUsageProperty {
                        property: "alpha".into(),
                        value: "first-string".into(),
                    },
                    CommetUsageProperty {
                        property: "4294967295".into(),
                        value: "not-index".into(),
                    },
                ]),
            },
            Some("caller-key".into()),
        ),
        CommetCall::TrackUsage(
            CommetUsageEvent {
                feature_code: "reports".into(),
                customer_id: user_id.into(),
                value: None,
                properties: None,
            },
            None,
        ),
    ]
}
