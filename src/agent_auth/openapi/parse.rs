use serde_json::{Map, Value, json};

use crate::AgentCapability;

#[derive(Debug, Clone)]
pub(super) struct ParsedCapability {
    pub capability: AgentCapability,
    pub method: String,
}

#[derive(Debug, Clone)]
pub(super) struct OpenApiOperation {
    pub capability: String,
    pub method: String,
    pub url: String,
    pub parameters: Vec<OpenApiParameter>,
    pub has_request_body: bool,
}

#[derive(Debug, Clone)]
pub(super) struct OpenApiParameter {
    pub name: String,
    pub location: String,
}

type OperationEntry<'a> = (
    &'a str,
    &'a str,
    &'a Map<String, Value>,
    &'a Map<String, Value>,
);

pub(super) fn parse_capabilities(spec: &Value) -> Vec<ParsedCapability> {
    operations(spec)
        .into_iter()
        .filter_map(|(method, _path, path_item, operation)| {
            let operation_id = operation
                .get("operationId")?
                .as_str()
                .filter(|operation_id| !operation_id.is_empty())?
                .to_owned();
            let parameters = merge_parameters(spec, path_item, operation);
            let request_body = operation.get("requestBody").map(|body| deref(spec, body));
            let input = build_input_schema(spec, &parameters, request_body);
            let output = build_output_schema(spec, operation);
            let description = operation
                .get("description")
                .and_then(Value::as_str)
                .or_else(|| operation.get("summary").and_then(Value::as_str))
                .unwrap_or(&operation_id)
                .to_owned();
            let mut capability = AgentCapability::new(operation_id, description);
            capability.input = input;
            capability.output = output;
            Some(ParsedCapability {
                capability,
                method: method.to_ascii_uppercase(),
            })
        })
        .collect()
}

pub(super) fn operation_map(spec: &Value, base_url: &str) -> Vec<OpenApiOperation> {
    let mut mapped: Vec<OpenApiOperation> = Vec::new();
    for (method, path, path_item, operation) in operations(spec) {
        let Some(capability) = operation
            .get("operationId")
            .and_then(Value::as_str)
            .filter(|operation_id| !operation_id.is_empty())
        else {
            continue;
        };
        let mapped_operation = OpenApiOperation {
            capability: capability.to_owned(),
            method: method.to_ascii_uppercase(),
            url: format!("{base_url}{path}"),
            parameters: merge_parameters(spec, path_item, operation)
                .into_iter()
                .filter_map(|parameter| {
                    Some(OpenApiParameter {
                        name: parameter.get("name")?.as_str()?.to_owned(),
                        location: parameter
                            .get("in")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    })
                })
                .collect(),
            has_request_body: operation
                .get("requestBody")
                .map(|body| deref(spec, body))
                .is_some_and(js_truthy),
        };
        if let Some(existing) = mapped
            .iter_mut()
            .find(|existing| existing.capability == capability)
        {
            *existing = mapped_operation;
        } else {
            mapped.push(mapped_operation);
        }
    }
    mapped
}

fn operations(spec: &Value) -> Vec<OperationEntry<'_>> {
    let mut operations = Vec::new();
    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        return operations;
    };
    for (path, path_item) in paths {
        let Some(path_item) = path_item.as_object() else {
            continue;
        };
        for (method, operation) in path_item {
            if matches!(
                method.as_str(),
                "parameters" | "servers" | "summary" | "description"
            ) {
                continue;
            }
            let Some(operation) = operation.as_object() else {
                continue;
            };
            operations.push((method.as_str(), path.as_str(), path_item, operation));
        }
    }
    operations
}

fn merge_parameters<'a>(
    spec: &'a Value,
    path_item: &'a Map<String, Value>,
    operation: &'a Map<String, Value>,
) -> Vec<&'a Map<String, Value>> {
    let mut merged: Vec<(String, &'a Map<String, Value>)> = Vec::new();
    for parameter in path_item
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
    {
        let Some(parameter) = deref(spec, parameter).as_object() else {
            continue;
        };
        let Some(name) = parameter
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let location = parameter
            .get("in")
            .map(js_string)
            .unwrap_or_else(|| "undefined".into());
        let key = format!("{location}:{name}");
        if let Some(existing) = merged.iter_mut().find(|(existing, _)| existing == &key) {
            existing.1 = parameter;
        } else {
            merged.push((key, parameter));
        }
    }
    merged.into_iter().map(|(_, parameter)| parameter).collect()
}

fn build_input_schema(
    spec: &Value,
    parameters: &[&Map<String, Value>],
    request_body: Option<&Value>,
) -> Option<Map<String, Value>> {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for parameter in parameters {
        let Some(name) = parameter.get("name").and_then(Value::as_str) else {
            continue;
        };
        let mut schema = parameter
            .get("schema")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(|| Map::from_iter([("type".into(), json!("string"))]));
        if let Some(description) = parameter
            .get("description")
            .and_then(Value::as_str)
            .filter(|description| !description.is_empty())
        {
            schema.insert("description".into(), json!(description));
        }
        properties.insert(name.into(), Value::Object(schema));
        if parameter.get("required").is_some_and(js_truthy) {
            required.push(Value::String(name.into()));
        }
    }
    if let Some(body_schema) = request_body
        .and_then(|body| body.get("content"))
        .and_then(|content| content.get("application/json"))
        .and_then(|content| content.get("schema"))
        .map(|schema| deref(spec, schema))
        .and_then(Value::as_object)
    {
        if let Some(body_properties) = body_schema.get("properties").and_then(Value::as_object) {
            for (name, schema) in body_properties {
                properties.insert(name.clone(), schema.clone());
            }
        }
        if let Some(body_required) = body_schema.get("required").and_then(Value::as_array) {
            for name in body_required {
                if !required.contains(name) {
                    required.push(name.clone());
                }
            }
        }
    }
    if properties.is_empty() {
        return None;
    }
    let mut schema = Map::from_iter([
        ("type".into(), json!("object")),
        ("properties".into(), Value::Object(properties)),
    ]);
    if !required.is_empty() {
        schema.insert("required".into(), Value::Array(required));
    }
    Some(schema)
}

fn build_output_schema(spec: &Value, operation: &Map<String, Value>) -> Option<Map<String, Value>> {
    let responses = operation.get("responses")?.as_object()?;
    let response = responses.get("200").or_else(|| responses.get("201"))?;
    let response = deref(spec, response);
    let schema = response
        .get("content")?
        .get("application/json")?
        .get("schema")?;
    deref(spec, schema).as_object().cloned()
}

fn deref<'a>(spec: &'a Value, node: &'a Value) -> &'a Value {
    let Some(reference) = node.get("$ref").and_then(Value::as_str) else {
        return node;
    };
    let Some(path) = reference.strip_prefix("#/") else {
        return node;
    };
    let mut resolved = spec;
    for part in path.split('/') {
        let Some(next) = resolved.get(part) else {
            return node;
        };
        resolved = next;
    }
    if resolved.is_null() { node } else { resolved }
}

pub(super) fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value
            .as_f64()
            .map(|value| ryu_js::Buffer::new().format(value).to_owned())
            .unwrap_or_else(|| value.to_string()),
        Value::String(value) => value.clone(),
        Value::Array(values) => values.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::openapi::test_support::fixture;
    use serde_json::json;

    #[test]
    fn site_example_merges_path_operation_body_and_response_schemas() {
        let spec = fixture();
        let parsed = parse_capabilities(&spec);
        assert_eq!(
            parsed
                .iter()
                .map(|entry| (&entry.capability.name, &entry.capability.description))
                .map(|(name, description)| (name.as_str(), description.as_str()))
                .collect::<Vec<_>>(),
            [
                ("messages.get", "Get a message"),
                ("messages.create", "Create a message")
            ]
        );
        assert_eq!(
            parsed[0].capability.input.as_ref().unwrap()["required"],
            json!(["id", "x-tenant"])
        );
        assert_eq!(
            parsed[0].capability.output.as_ref().unwrap(),
            json!({"type":"object","properties":{"id":{"type":"string"}}})
                .as_object()
                .unwrap()
        );
        assert_eq!(
            parsed[1].capability.input.as_ref().unwrap()["required"],
            json!(["id", "subject"])
        );
    }

    #[test]
    fn stringifies_json_numbers_like_javascript() {
        assert_eq!(js_string(&json!(1.0)), "1");
        assert_eq!(js_string(&json!(1e21)), "1e+21");
        assert_eq!(js_string(&json!(-0.0)), "0");
    }

    #[test]
    fn operation_map_uses_the_last_duplicate_operation_id() {
        let spec = json!({"paths": {
            "/first": {"get": {"operationId": "duplicate"}},
            "/second": {"post": {"operationId": "duplicate"}}
        }});
        let mapped = operation_map(&spec, "https://upstream.example");
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].method, "POST");
        assert_eq!(mapped[0].url, "https://upstream.example/second");
    }
}
