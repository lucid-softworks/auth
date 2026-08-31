use super::{
    FieldSchemaKind, OpenApiComponents, OpenApiEndpoint, OpenApiInfo, OpenApiMediaType,
    OpenApiModel, OpenApiModelSchema, OpenApiOperation, OpenApiParameter, OpenApiPath,
    OpenApiRequestBody, OpenApiSchema, OpenApiServer, OpenApiTag,
    fields::{model_field_schema, request_field_schema},
    responses::standard_responses,
};
use crate::{AuthService, DatabaseModel, PluginHttpMethod};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

#[derive(Deserialize)]
struct CoreFixture {
    components: CoreComponents,
    paths: BTreeMap<String, OpenApiPath>,
}

#[derive(Deserialize)]
struct CoreComponents {
    schemas: BTreeMap<String, OpenApiModelSchema>,
}

/// Generate the Better Auth 1.7.2 OpenAPI document for native callers.
pub fn generate_open_api_schema(service: &AuthService) -> OpenApiSchema {
    generate_open_api_schema_with_base_url(service, direct_base_url(service))
}

pub(crate) fn generate_open_api_schema_with_base_url(
    service: &AuthService,
    base_url: String,
) -> OpenApiSchema {
    let mut fixture: CoreFixture =
        serde_json::from_str(include_str!("core.json")).expect("pinned OpenAPI fixture is valid");
    for path in service.disabled_paths() {
        fixture.paths.remove(&to_open_api_path(path));
    }
    merge_user_input_fields(service, &mut fixture.paths);
    merge_core_model_fields(service, &mut fixture.components.schemas);
    merge_plugin_models(service, &mut fixture.components.schemas);
    merge_plugin_endpoints(service, &mut fixture.paths);

    OpenApiSchema {
        openapi: "3.1.1".into(),
        info: OpenApiInfo {
            title: "Better Auth".into(),
            description: "API Reference for your Better Auth Instance".into(),
            version: "1.1.0".into(),
        },
        components: OpenApiComponents {
            schemas: fixture.components.schemas,
            security_schemes: BTreeMap::from([
                (
                    "apiKeyCookie".into(),
                    json!({
                        "type": "apiKey",
                        "in": "cookie",
                        "name": "apiKeyCookie",
                        "description": "API Key authentication via cookie",
                    }),
                ),
                (
                    "bearerAuth".into(),
                    json!({
                        "type": "http",
                        "scheme": "bearer",
                        "description": "Bearer token authentication",
                    }),
                ),
            ]),
        },
        security: vec![BTreeMap::from([
            ("apiKeyCookie".into(), Vec::new()),
            ("bearerAuth".into(), Vec::new()),
        ])],
        servers: vec![OpenApiServer { url: base_url }],
        tags: vec![OpenApiTag {
            name: "Default".into(),
            description: "Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin.".into(),
        }],
        paths: fixture.paths,
    }
}

fn direct_base_url(service: &AuthService) -> String {
    let Some(configured) = service.open_api_configured_base_url() else {
        return String::new();
    };
    let mut url = configured.clone();
    url.set_path(service.configured_base_path());
    url.set_query(None);
    url.set_fragment(None);
    url.as_str().trim_end_matches('/').to_owned()
}

fn merge_user_input_fields(service: &AuthService, paths: &mut BTreeMap<String, OpenApiPath>) {
    let fields = service.database_schema_fields(DatabaseModel::User);
    if fields.is_empty() {
        return;
    }
    for (path, required_on_signup) in [("/sign-up/email", true), ("/update-user", false)] {
        let Some(operation) = paths.get_mut(path).and_then(|path| path.get_mut("post")) else {
            continue;
        };
        let Some(schema) = operation
            .request_body
            .as_mut()
            .and_then(|body| body.content.get_mut("application/json"))
            .map(|media| &mut media.schema)
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let mut required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let properties = schema
            .entry("properties")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("core request properties are an object");
        for (name, field) in fields {
            if !field.input || properties.contains_key(name) {
                continue;
            }
            properties.insert(name.clone(), request_field_schema(field));
            if required_on_signup
                && field.required
                && !field.has_default()
                && !required.iter().any(|value| value == name)
            {
                required.push(Value::String(name.clone()));
            }
        }
        if !required.is_empty() {
            schema.insert("required".into(), Value::Array(required));
        }
    }
}

fn merge_core_model_fields(
    service: &AuthService,
    schemas: &mut BTreeMap<String, OpenApiModelSchema>,
) {
    for (model, name) in [
        (DatabaseModel::User, "User"),
        (DatabaseModel::Session, "Session"),
        (DatabaseModel::Account, "Account"),
        (DatabaseModel::Verification, "Verification"),
        (DatabaseModel::Organization, "Organization"),
    ] {
        let Some(schema) = schemas.get_mut(name) else {
            continue;
        };
        for (field_name, field) in service.database_schema_fields(model) {
            schema
                .properties
                .insert(field_name.clone(), model_field_schema(field));
            if field.required
                && field.returned
                && !schema
                    .required
                    .iter()
                    .any(|required| required == field_name)
            {
                schema.required.push(field_name.clone());
            }
        }
    }
}

fn merge_plugin_models(service: &AuthService, schemas: &mut BTreeMap<String, OpenApiModelSchema>) {
    for OpenApiModel { name, fields } in service.open_api_models() {
        let model_name = capitalize_first(&name);
        let mut properties =
            BTreeMap::from([("id".into(), json!({ "type": "string", "readOnly": true }))]);
        let mut required = vec!["id".into()];
        for (name, field) in fields {
            properties.insert(name.clone(), model_field_schema(&field));
            if field.required && field.returned {
                required.push(name);
            }
        }
        schemas.insert(
            model_name,
            OpenApiModelSchema {
                schema_type: "object".into(),
                properties,
                required,
                extensions: BTreeMap::new(),
            },
        );
    }
}

fn merge_plugin_endpoints(service: &AuthService, paths: &mut BTreeMap<String, OpenApiPath>) {
    let disabled = service.disabled_paths().iter().collect::<HashSet<_>>();
    let mut used_operation_ids = paths
        .values()
        .flat_map(BTreeMap::values)
        .filter_map(|operation| operation.operation_id.clone())
        .collect::<HashSet<_>>();
    for (plugin_id, endpoints) in service.open_api_endpoints() {
        if plugin_id == "open-api" {
            continue;
        }
        let default_tag = capitalize_first(plugin_id);
        for endpoint in endpoints {
            if endpoint.server_only || disabled.contains(&endpoint.path) {
                continue;
            }
            add_plugin_endpoint(paths, &endpoint, &default_tag, &mut used_operation_ids);
        }
    }
}

fn add_plugin_endpoint(
    paths: &mut BTreeMap<String, OpenApiPath>,
    endpoint: &OpenApiEndpoint,
    default_tag: &str,
    used_operation_ids: &mut HashSet<String>,
) {
    let path = to_open_api_path(&endpoint.path);
    let parameters = endpoint_parameters(endpoint);
    for method in &endpoint.methods {
        let method_name = method_name(*method);
        let operation_id = unique_operation_id(
            endpoint.operation_id.as_deref(),
            method_name,
            used_operation_ids,
        );
        let request_body = if matches!(
            method,
            PluginHttpMethod::Post | PluginHttpMethod::Patch | PluginHttpMethod::Put
        ) {
            endpoint.request_body.clone().or_else(|| {
                endpoint.body.as_ref().map(|schema| OpenApiRequestBody {
                    required: Some(!schema.accepts_undefined()),
                    content: BTreeMap::from([(
                        "application/json".into(),
                        OpenApiMediaType {
                            schema: schema.to_open_api_value(),
                            extensions: BTreeMap::new(),
                        },
                    )]),
                    extensions: BTreeMap::new(),
                })
            })
        } else {
            None
        };
        paths.entry(path.clone()).or_default().insert(
            method_name.to_ascii_lowercase(),
            OpenApiOperation {
                tags: if endpoint.tags.is_empty() {
                    vec![default_tag.into()]
                } else {
                    endpoint.tags.clone()
                },
                description: endpoint.description.clone(),
                operation_id,
                security: vec![BTreeMap::from([("bearerAuth".into(), Vec::new())])],
                parameters: parameters.clone(),
                request_body,
                responses: standard_responses(&endpoint.responses),
            },
        );
    }
}

fn endpoint_parameters(endpoint: &OpenApiEndpoint) -> Vec<OpenApiParameter> {
    let mut parameters = if let Some(parameters) = &endpoint.parameters {
        parameters.clone()
    } else if let Some(query) = &endpoint.query
        && let FieldSchemaKind::Object(fields) = &query.kind
    {
        fields
            .iter()
            .map(|(name, schema)| OpenApiParameter::new(name, "query", schema.to_open_api_value()))
            .collect()
    } else {
        Vec::new()
    };
    let existing = parameters
        .iter()
        .map(|parameter| format!("{}:{}", parameter.location, parameter.name))
        .collect::<HashSet<_>>();
    for segment in endpoint
        .path
        .split('/')
        .filter_map(|part| part.strip_prefix(':'))
    {
        if !existing.contains(&format!("path:{segment}")) {
            let mut parameter = OpenApiParameter::new(segment, "path", json!({ "type": "string" }));
            parameter.required = Some(true);
            parameters.push(parameter);
        }
    }
    parameters
}

fn to_open_api_path(path: &str) -> String {
    path.split('/')
        .map(|part| {
            part.strip_prefix(':')
                .map_or_else(|| part.to_owned(), |name| format!("{{{name}}}"))
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn unique_operation_id(
    operation_id: Option<&str>,
    method: &str,
    used: &mut HashSet<String>,
) -> Option<String> {
    let operation_id = operation_id?;
    if used.insert(operation_id.into()) {
        return Some(operation_id.into());
    }
    let mut suffix = method.to_ascii_lowercase();
    if let Some(first) = suffix.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    let base = format!("{operation_id}{suffix}");
    if used.insert(base.clone()) {
        return Some(base);
    }
    for index in 2.. {
        let candidate = format!("{base}{index}");
        if used.insert(candidate.clone()) {
            return Some(candidate);
        }
    }
    unreachable!()
}

const fn method_name(method: PluginHttpMethod) -> &'static str {
    match method {
        PluginHttpMethod::Get => "GET",
        PluginHttpMethod::Post => "POST",
        PluginHttpMethod::Put => "PUT",
        PluginHttpMethod::Patch => "PATCH",
        PluginHttpMethod::Delete => "DELETE",
    }
}

fn capitalize_first(value: &str) -> String {
    let mut characters = value.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + characters.as_str()
    })
}
