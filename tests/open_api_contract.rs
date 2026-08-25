#![cfg(feature = "axum")]

#[path = "open_api_contract/fixture.rs"]
mod fixture;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use fixture::{MetadataFixturePlugin, body, operation_count, service};
use lucid_auth::{
    AdditionalField, AdditionalFieldType, OpenApiConfig, OpenApiPlugin, OpenApiSchema,
    OpenApiTheme, generate_open_api_schema,
};
use serde_json::{Value, json};
use tower::ServiceExt;

#[test]
fn default_document_has_exact_core_inventory_and_envelope() {
    let service = service(|config| {
        config.add_plugin(OpenApiPlugin::default()).unwrap();
    });
    let document = generate_open_api_schema(&service);
    assert_eq!(document.openapi, "3.1.1");
    assert_eq!(document.info.title, "Better Auth");
    assert_eq!(document.info.version, "1.1.0");
    assert_eq!(document.servers[0].url, "");
    assert_eq!(document.paths.len(), 30);
    assert_eq!(operation_count(&document), 32);
    assert_eq!(
        document.paths["/callback/{id}"].keys().collect::<Vec<_>>(),
        [&"get".to_owned(), &"post".to_owned()]
    );
    assert_eq!(
        document.paths["/sign-up/email"]["post"]
            .operation_id
            .as_deref(),
        Some("signUpWithEmailAndPassword")
    );
    assert!(!document.paths.contains_key("/reference"));
    assert!(!document.paths.contains_key("/open-api/generate-schema"));
    assert_eq!(
        document.components.security_schemes["apiKeyCookie"]["name"],
        "apiKeyCookie"
    );
}

#[test]
fn generator_applies_disabled_paths_plugin_metadata_models_and_user_fields() {
    let service = service(|config| {
        config
            .set_base_url("https://auth.example.test/custom")
            .unwrap();
        config.disabled_paths = vec!["/verify-password".into(), "/fixture-disabled".into()];
        config.user.additional_fields.insert(
            "timezone".into(),
            AdditionalField::new(AdditionalFieldType::String).default_value(json!("UTC")),
        );
        config.user.additional_fields.insert(
            "internal".into(),
            AdditionalField::new(AdditionalFieldType::Json).input(false),
        );
        config.user.additional_fields.insert(
            "tier".into(),
            AdditionalField::new(AdditionalFieldType::StringLiteral(&["free", "paid"])),
        );
        config.add_plugin(MetadataFixturePlugin).unwrap();
        config.add_plugin(OpenApiPlugin::default()).unwrap();
    });
    let document = generate_open_api_schema(&service);
    assert_eq!(document.servers[0].url, "https://auth.example.test/custom");
    assert!(!document.paths.contains_key("/verify-password"));
    assert!(!document.paths.contains_key("/fixture-disabled"));
    assert!(!document.paths.contains_key("/fixture-hidden"));
    assert_fixture_operations(&document);
    assert_user_input_fields(&document);
    assert_component_models(&document);
}

fn assert_fixture_operations(document: &OpenApiSchema) {
    let fixture = &document.paths["/fixture/{id}"];
    assert_eq!(fixture.len(), 2);
    assert_eq!(fixture["get"].tags, ["Fixtures"]);
    assert_eq!(
        fixture["get"].operation_id.as_deref(),
        Some("getSessionGet")
    );
    assert_eq!(
        fixture["post"].operation_id.as_deref(),
        Some("getSessionPost2")
    );
    assert_eq!(fixture["get"].parameters.len(), 3);
    assert_eq!(fixture["get"].parameters[2].location, "path");
    assert_eq!(fixture["get"].parameters[2].required, Some(true));
    assert!(fixture["get"].request_body.is_none());
    assert_eq!(
        fixture["post"].request_body.as_ref().unwrap().required,
        Some(true)
    );
    assert_eq!(
        fixture["post"].responses["400"].description,
        "Fixture bad request"
    );
    assert_eq!(
        fixture["post"].responses["401"].description,
        "Unauthorized. Due to missing or invalid authentication."
    );
}

fn assert_user_input_fields(document: &OpenApiSchema) {
    let sign_up = &document.paths["/sign-up/email"]["post"]
        .request_body
        .as_ref()
        .unwrap()
        .content["application/json"]
        .schema;
    assert_eq!(
        sign_up["properties"]["timezone"],
        json!({ "type": "string", "default": "UTC" })
    );
    assert!(sign_up["properties"].get("internal").is_none());
    assert_eq!(
        sign_up["properties"]["tier"],
        json!({ "type": "string", "enum": ["free", "paid"] })
    );
    assert!(
        !sign_up["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "timezone")
    );
    let update = &document.paths["/update-user"]["post"]
        .request_body
        .as_ref()
        .unwrap()
        .content["application/json"]
        .schema;
    assert!(update["properties"].get("timezone").is_some());
    assert!(
        update
            .get("required")
            .and_then(Value::as_array)
            .is_none_or(|required| !required.iter().any(|value| value == "timezone"))
    );
}

fn assert_component_models(document: &OpenApiSchema) {
    assert_eq!(
        document.components.schemas["User"].properties["internal"],
        json!({ "type": "json", "readOnly": true })
    );
    assert_eq!(
        document.components.schemas["User"].properties["tier"],
        json!({ "type": ["free", "paid"] })
    );
    let model = &document.components.schemas["FixtureRecord"];
    assert_eq!(
        model.properties["createdAt"],
        json!({ "type": "string", "format": "date-time" })
    );
    assert_eq!(
        model.properties["labels"],
        json!({ "type": "array", "items": { "type": "string" }, "default": ["one"], "readOnly": true })
    );
    assert_eq!(model.required, ["id", "createdAt"]);
}

#[tokio::test]
async fn axum_schema_and_scalar_routes_have_exact_method_and_content_boundaries() {
    let service = service(|config| config.add_plugin(OpenApiPlugin::default()).unwrap());
    let app = lucid_auth::axum::router(service);
    let schema = app
        .clone()
        .oneshot(
            Request::get("/api/auth/open-api/generate-schema")
                .header(header::HOST, "docs.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(schema.status(), StatusCode::OK);
    assert_eq!(schema.headers()[header::CONTENT_TYPE], "application/json");
    let document: Value = serde_json::from_slice(&body(schema).await).unwrap();
    assert_eq!(
        document["servers"][0]["url"],
        "http://docs.example.test/api/auth"
    );

    for method in [Method::HEAD, Method::POST] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/api/auth/open-api/generate-schema")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(body(response).await.is_empty());
    }

    let reference = app
        .clone()
        .oneshot(
            Request::get("/api/auth/reference")
                .header(header::HOST, "docs.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reference.status(), StatusCode::OK);
    assert_eq!(reference.headers()[header::CONTENT_TYPE], "text/html");
    let html = String::from_utf8(body(reference).await).unwrap();
    assert!(html.contains("id=\"api-reference\""));
    assert!(html.contains("https://cdn.jsdelivr.net/npm/@scalar/api-reference"));
    assert!(html.contains("theme: \"default\""));
    assert!(html.contains("Better Auth API"));

    let head = app
        .oneshot(
            Request::head("/api/auth/reference")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::NOT_FOUND);
    assert!(body(head).await.is_empty());
}

#[tokio::test]
async fn custom_reference_disabled_ui_nonce_and_theme_match_configuration() {
    let custom_service = service(|config| {
        config
            .add_plugin(OpenApiPlugin::new(OpenApiConfig {
                path: "/docs".into(),
                disable_default_reference: false,
                theme: OpenApiTheme::Moon,
                nonce: Some("nonce-value".into()),
            }))
            .unwrap();
    });
    let app = lucid_auth::axum::router(custom_service);
    assert_eq!(
        app.clone()
            .oneshot(
                Request::get("/api/auth/reference")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let response = app
        .oneshot(Request::get("/api/auth/docs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = String::from_utf8(body(response).await).unwrap();
    assert_eq!(html.matches("nonce=\"nonce-value\"").count(), 2);
    assert!(html.contains("theme: \"moon\""));

    let disabled = service(|config| {
        config
            .add_plugin(OpenApiPlugin::new(OpenApiConfig {
                disable_default_reference: true,
                ..OpenApiConfig::default()
            }))
            .unwrap();
    });
    let app = lucid_auth::axum::router(disabled);
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/reference")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert!(body(response).await.is_empty());
    assert_eq!(
        app.oneshot(
            Request::get("/api/auth/open-api/generate-schema")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn disabled_paths_are_excluded_and_return_better_auth_not_found() {
    let service = service(|config| {
        config.disabled_paths = vec!["/verify-password".into()];
        config.add_plugin(OpenApiPlugin::default()).unwrap();
    });
    assert!(
        !generate_open_api_schema(&service)
            .paths
            .contains_key("/verify-password")
    );
    let response = lucid_auth::axum::router(service)
        .oneshot(
            Request::post("/api/auth/verify-password")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "password": "secret" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body(response).await, b"Not Found");
}

#[tokio::test]
async fn plugin_routes_with_distinct_methods_can_share_one_path() {
    let service = service(|config| config.add_plugin(MetadataFixturePlugin).unwrap());
    let app = lucid_auth::axum::router(service);
    for (method, expected) in [(Method::GET, "get"), (Method::POST, "post")] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/api/auth/fixture/record")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&body(response).await).unwrap(),
            json!({ "method": expected })
        );
    }
}
