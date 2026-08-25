use axum::{
    Json,
    routing::{get, post},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthPlugin, AuthService, AxumPluginRoute,
    FieldSchema, FieldSchemaKind, MemoryStore, OpenApiConfig, OpenApiEndpoint, OpenApiModel,
    OpenApiParameter, OpenApiPlugin, OpenApiResponse, OpenApiTheme, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, generate_open_api_schema,
};
use serde_json::json;
use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: Cow::Borrowed("/fixture/:id"),
        client_method: "fixture.read",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed("/fixture/:id"),
        client_method: "fixture.write",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: Cow::Borrowed("/fixture-hidden"),
        client_method: "fixture.hidden",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: Cow::Borrowed("/fixture-disabled"),
        client_method: "fixture.disabled",
    },
];

pub(super) struct MetadataFixturePlugin;

impl AuthPlugin for MetadataFixturePlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "fixture-plugin",
            display_name: "Fixture plugin",
            version: "1.7.1",
            provenance: lucid_auth::PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn open_api_endpoints(&self) -> Vec<OpenApiEndpoint> {
        let query = FieldSchema::new(FieldSchemaKind::Object(BTreeMap::from([
            ("page".into(), FieldSchema::new(FieldSchemaKind::Number)),
            (
                "filter".into(),
                FieldSchema::new(FieldSchemaKind::Optional(Box::new(FieldSchema::new(
                    FieldSchemaKind::String {
                        min_length: None,
                        max_length: None,
                    },
                )))),
            ),
        ])));
        let body = FieldSchema::new(FieldSchemaKind::Object(BTreeMap::from([(
            "name".into(),
            FieldSchema::new(FieldSchemaKind::String {
                min_length: Some(1),
                max_length: None,
            }),
        )])));
        let mut endpoint = OpenApiEndpoint::new(
            "/fixture/:id",
            vec![PluginHttpMethod::Get, PluginHttpMethod::Post],
        );
        endpoint.tags = vec!["Fixtures".into()];
        endpoint.description = Some("Fixture operation".into());
        endpoint.operation_id = Some("getSession".into());
        endpoint.query = Some(query);
        endpoint.body = Some(body);
        endpoint.responses.insert(
            "400".into(),
            OpenApiResponse {
                description: "Fixture bad request".into(),
                content: None,
                extensions: BTreeMap::new(),
            },
        );
        let mut hidden = OpenApiEndpoint::new("/fixture-hidden", vec![PluginHttpMethod::Get]);
        hidden.server_only = true;
        let disabled = OpenApiEndpoint::new("/fixture-disabled", vec![PluginHttpMethod::Get]);
        vec![endpoint, hidden, disabled]
    }

    fn open_api_models(&self) -> Vec<OpenApiModel> {
        vec![OpenApiModel {
            name: "fixtureRecord".into(),
            fields: BTreeMap::from([
                (
                    "createdAt".into(),
                    AdditionalField::new(AdditionalFieldType::Date),
                ),
                (
                    "labels".into(),
                    AdditionalField::new(AdditionalFieldType::StringArray)
                        .optional()
                        .input(false)
                        .default_value(json!(["one"])),
                ),
            ]),
        }]
    }

    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        vec![
            AxumPluginRoute::new(
                "/fixture/{id}",
                get(|| async { Json(json!({ "method": "get" })) }),
            ),
            AxumPluginRoute::new(
                "/fixture/{id}",
                post(|| async { Json(json!({ "method": "post" })) }),
            ),
        ]
    }
}

pub(super) fn service(configure: impl FnOnce(&mut AuthConfig)) -> Arc<AuthService> {
    let mut config = AuthConfig::new([143_u8; 32]).unwrap();
    configure(&mut config);
    Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config))
}

pub(super) fn operation_count(document: &lucid_auth::OpenApiSchema) -> usize {
    document.paths.values().map(BTreeMap::len).sum()
}

pub(super) async fn body(response: axum::response::Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[test]
fn defaults_themes_and_descriptor_match_better_auth_171() {
    assert_eq!(OpenApiPlugin::default().config(), &OpenApiConfig::default());
    assert_eq!(OpenApiConfig::default().path, "/reference");
    assert!(!OpenApiConfig::default().disable_default_reference);
    assert_eq!(OpenApiConfig::default().nonce, None);
    let themes = [
        OpenApiTheme::Alternate,
        OpenApiTheme::Default,
        OpenApiTheme::Moon,
        OpenApiTheme::Purple,
        OpenApiTheme::Solarized,
        OpenApiTheme::BluePlanet,
        OpenApiTheme::Saturn,
        OpenApiTheme::Kepler,
        OpenApiTheme::Mars,
        OpenApiTheme::DeepSpace,
        OpenApiTheme::Laserwave,
        OpenApiTheme::None,
    ];
    assert_eq!(
        themes.map(OpenApiTheme::as_str),
        [
            "alternate",
            "default",
            "moon",
            "purple",
            "solarized",
            "bluePlanet",
            "saturn",
            "kepler",
            "mars",
            "deepSpace",
            "laserwave",
            "none"
        ]
    );
    let descriptor = OpenApiPlugin::default().descriptor();
    assert_eq!(descriptor.id, "open-api");
    assert_eq!(descriptor.version, "1.7.1");
    assert_eq!(descriptor.endpoints.len(), 2);
    assert_eq!(descriptor.endpoints[0].path, "/open-api/generate-schema");
    assert_eq!(descriptor.endpoints[1].path, "/reference");
    assert!(descriptor.client.is_none());
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
}

#[test]
fn explicit_path_parameters_replace_inference_without_duplication() {
    let mut endpoint = OpenApiEndpoint::new("/resource/:id", vec![PluginHttpMethod::Get]);
    let mut parameter = OpenApiParameter::new("id", "path", json!({ "type": "integer" }));
    parameter.required = Some(true);
    endpoint.parameters = Some(vec![parameter]);
    struct ExplicitParameterPlugin(OpenApiEndpoint);
    impl AuthPlugin for ExplicitParameterPlugin {
        fn descriptor(&self) -> PluginDescriptor {
            PluginDescriptor {
                id: "explicit",
                display_name: "Explicit",
                version: "1.7.1",
                provenance: lucid_auth::PluginProvenance::lucid_extension(),
                dependencies: &[],
                conflicts: &[],
                endpoints: Cow::Owned(vec![PluginEndpoint {
                    method: PluginHttpMethod::Get,
                    path: Cow::Borrowed("/resource/:id"),
                    client_method: "resource",
                }]),
                cookies: &[],
                rate_limits: &[],
                middleware: &[],
                client: None,
            }
        }

        fn open_api_endpoints(&self) -> Vec<OpenApiEndpoint> {
            vec![self.0.clone()]
        }
    }
    let service = service(|config| {
        config
            .add_plugin(ExplicitParameterPlugin(endpoint))
            .unwrap();
    });
    let document = generate_open_api_schema(&service);
    let parameters = &document.paths["/resource/{id}"]["get"].parameters;
    assert_eq!(parameters.len(), 1);
    assert_eq!(parameters[0].schema, json!({ "type": "integer" }));
}
