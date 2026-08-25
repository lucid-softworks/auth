use super::support::{fixture, get, post};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, CommetFeature, CommetOptions, CommetPlugin,
    CommetPortalOptions, CommetSubscriptionsOptions, CommetWebhooksOptions, MemoryStore,
    PluginHttpMethod,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn empty_and_selective_composition_only_installs_selected_routes() {
    let empty = fixture(Vec::new(), true).await;
    assert_eq!(
        get(&empty, "/api/auth/commet/portal").await.0,
        StatusCode::NOT_FOUND
    );

    let portal = fixture(
        vec![CommetFeature::Portal(CommetPortalOptions::default())],
        true,
    )
    .await;
    assert_eq!(
        get(&portal, "/api/auth/commet/portal").await.0,
        StatusCode::OK
    );
    assert_eq!(
        get(&portal, "/api/auth/commet/features").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn later_duplicate_portal_configuration_wins_and_replaces_return_url() {
    let fixture = fixture(
        vec![
            CommetFeature::Portal(CommetPortalOptions {
                return_url: Some("https://first.example.test".into()),
            }),
            CommetFeature::Portal(CommetPortalOptions {
                return_url: Some("https://last.example.test/billing?tab=plans".into()),
            }),
        ],
        true,
    )
    .await;
    fixture
        .client
        .respond(
            "portal",
            serde_json::json!({
                "portalUrl": "https://portal.commet.test/session?return_url=old&keep=1&return_url=older"
            }),
        )
        .await;
    let (status, body) = get(&fixture, "/api/auth/commet/portal").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["url"],
        "https://portal.commet.test/session?return_url=https%3A%2F%2Flast.example.test%2Fbilling%3Ftab%3Dplans&keep=1"
    );
}

#[tokio::test]
async fn every_individual_selection_has_its_exact_descriptor_and_runtime_routes() {
    for (selected, feature, expected_descriptor) in selection_cases() {
        let fixture = fixture(vec![feature.clone()], true).await;
        let plugin = CommetPlugin::new(CommetOptions::new(fixture.client.clone(), vec![feature]));
        let actual_descriptor = plugin
            .descriptor()
            .endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.method,
                    endpoint.path.as_ref().to_owned(),
                    endpoint.client_method,
                )
            })
            .collect::<Vec<_>>();
        let expected_descriptor = expected_descriptor
            .into_iter()
            .map(|(method, path, client_method)| (method, path.to_owned(), client_method))
            .collect::<Vec<_>>();
        assert_eq!(actual_descriptor, expected_descriptor, "{selected}");

        assert_runtime_selection(&fixture, selected).await;
    }
}

type SelectionCase = (
    &'static str,
    CommetFeature,
    Vec<(PluginHttpMethod, &'static str, &'static str)>,
);

fn selection_cases() -> Vec<SelectionCase> {
    vec![
        (
            "portal",
            CommetFeature::Portal(CommetPortalOptions::default()),
            vec![(PluginHttpMethod::Get, "/commet/portal", "customer.portal")],
        ),
        (
            "subscriptions",
            CommetFeature::Subscriptions(CommetSubscriptionsOptions::default()),
            vec![
                (
                    PluginHttpMethod::Get,
                    "/commet/subscription",
                    "subscription.get",
                ),
                (
                    PluginHttpMethod::Post,
                    "/commet/subscription/cancel",
                    "subscription.cancel",
                ),
            ],
        ),
        (
            "features",
            CommetFeature::Features,
            vec![
                (PluginHttpMethod::Get, "/commet/features", "features.list"),
                (
                    PluginHttpMethod::Get,
                    "/commet/features/:code",
                    "features.get",
                ),
                (
                    PluginHttpMethod::Get,
                    "/commet/features/:code/check",
                    "features.check",
                ),
                (
                    PluginHttpMethod::Get,
                    "/commet/features/:code/can-use",
                    "features.canUse",
                ),
            ],
        ),
        (
            "usage",
            CommetFeature::Usage,
            vec![(PluginHttpMethod::Post, "/commet/usage/track", "usage.track")],
        ),
        (
            "seats",
            CommetFeature::Seats,
            vec![
                (PluginHttpMethod::Get, "/commet/seats", "seats.list"),
                (PluginHttpMethod::Post, "/commet/seats/add", "seats.add"),
                (
                    PluginHttpMethod::Post,
                    "/commet/seats/remove",
                    "seats.remove",
                ),
                (PluginHttpMethod::Post, "/commet/seats/set", "seats.set"),
                (
                    PluginHttpMethod::Post,
                    "/commet/seats/set-all",
                    "seats.setAll",
                ),
            ],
        ),
        (
            "webhooks",
            CommetFeature::Webhooks(CommetWebhooksOptions::new("selection-secret")),
            vec![(PluginHttpMethod::Post, "/commet/webhooks", "commetWebhooks")],
        ),
    ]
}

async fn assert_runtime_selection(fixture: &super::support::Fixture, selected: &str) {
    for probe in route_probes() {
        let status = match probe.method {
            PluginHttpMethod::Get => get(fixture, probe.path).await.0,
            PluginHttpMethod::Post => post(fixture, probe.path, probe.body.clone()).await.0,
            _ => unreachable!("Commet 8.1.0 only exposes GET and POST routes"),
        };
        let expected = if probe.group == selected {
            probe.selected_status
        } else {
            StatusCode::NOT_FOUND
        };
        assert_eq!(status, expected, "{selected}: {}", probe.path);
    }
}

struct RouteProbe {
    group: &'static str,
    method: PluginHttpMethod,
    path: &'static str,
    body: Value,
    selected_status: StatusCode,
}

fn route_probes() -> Vec<RouteProbe> {
    vec![
        get_probe("portal", "/api/auth/commet/portal"),
        get_probe("subscriptions", "/api/auth/commet/subscription"),
        post_probe(
            "subscriptions",
            "/api/auth/commet/subscription/cancel",
            json!({}),
        ),
        get_probe("features", "/api/auth/commet/features"),
        get_probe("features", "/api/auth/commet/features/reports"),
        get_probe("features", "/api/auth/commet/features/reports/check"),
        get_probe("features", "/api/auth/commet/features/reports/can-use"),
        post_probe(
            "usage",
            "/api/auth/commet/usage/track",
            json!({"feature": "reports"}),
        ),
        get_probe("seats", "/api/auth/commet/seats"),
        post_probe(
            "seats",
            "/api/auth/commet/seats/add",
            json!({"featureCode": "members", "count": 1}),
        ),
        post_probe(
            "seats",
            "/api/auth/commet/seats/remove",
            json!({"featureCode": "members", "count": 1}),
        ),
        post_probe(
            "seats",
            "/api/auth/commet/seats/set",
            json!({"featureCode": "members", "count": 1}),
        ),
        post_probe(
            "seats",
            "/api/auth/commet/seats/set-all",
            json!({"seats": {"members": 1}}),
        ),
        RouteProbe {
            group: "webhooks",
            method: PluginHttpMethod::Post,
            path: "/api/auth/commet/webhooks",
            body: json!({"type": "customer.created"}),
            selected_status: StatusCode::UNAUTHORIZED,
        },
    ]
}

fn get_probe(group: &'static str, path: &'static str) -> RouteProbe {
    RouteProbe {
        group,
        method: PluginHttpMethod::Get,
        path,
        body: Value::Null,
        selected_status: StatusCode::OK,
    }
}

fn post_probe(group: &'static str, path: &'static str, body: Value) -> RouteProbe {
    RouteProbe {
        group,
        method: PluginHttpMethod::Post,
        path,
        body,
        selected_status: StatusCode::OK,
    }
}

#[tokio::test]
async fn auth_config_without_commet_installs_no_commet_routes() {
    let mut config = AuthConfig::new([82_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    let response = lucid_auth::axum::router(service)
        .oneshot(
            Request::get("/api/auth/commet/portal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
