use crate::scim::{SCIM_ENTERPRISE_USER_SCHEMA, ScimError, ScimErrorType};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::scim::axum) enum AttributeProjection {
    Default,
    Include(HashSet<String>),
    Exclude(HashSet<String>),
}

pub(in crate::scim::axum) fn projection(
    query: &HashMap<String, String>,
    resource_type: &str,
) -> Result<AttributeProjection, ScimError> {
    let attributes = paths(query.get("attributes"), "attributes", resource_type)?;
    let excluded = paths(
        query.get("excludedAttributes"),
        "excludedAttributes",
        resource_type,
    )?;
    if !attributes.is_empty() && !excluded.is_empty() {
        return Err(invalid_value(
            "attributes and excludedAttributes cannot be used together",
        ));
    }
    if !attributes.is_empty() {
        Ok(AttributeProjection::Include(attributes))
    } else if !excluded.is_empty() {
        Ok(AttributeProjection::Exclude(excluded))
    } else {
        Ok(AttributeProjection::Default)
    }
}

fn paths(
    value: Option<&String>,
    parameter: &str,
    resource_type: &str,
) -> Result<HashSet<String>, ScimError> {
    let mut paths = HashSet::new();
    let Some(value) = value else {
        return Ok(paths);
    };
    if value.trim().is_empty() {
        return Ok(paths);
    }
    for part in value.split(',') {
        let path = part.trim();
        if path.is_empty() || path.chars().any(char::is_whitespace) {
            return Err(invalid_value(format!(
                "{parameter} must be a comma-separated list of attribute paths"
            )));
        }
        paths.insert(response_path(resource_type, path).to_ascii_lowercase());
    }
    Ok(paths)
}

fn response_path(resource_type: &str, path: &str) -> String {
    if resource_type != "User" {
        return strip_core_prefix(path, resource_type).to_owned();
    }
    let enterprise_prefix = format!("{SCIM_ENTERPRISE_USER_SCHEMA}:");
    if path.len() >= enterprise_prefix.len()
        && path[..enterprise_prefix.len()].eq_ignore_ascii_case(&enterprise_prefix)
    {
        return format!(
            "{SCIM_ENTERPRISE_USER_SCHEMA}.{}",
            &path[enterprise_prefix.len()..]
        );
    }
    if path.eq_ignore_ascii_case("manager") || path.to_ascii_lowercase().starts_with("manager.") {
        return format!("{SCIM_ENTERPRISE_USER_SCHEMA}.{path}");
    }
    strip_core_prefix(path, resource_type).to_owned()
}

fn strip_core_prefix<'a>(path: &'a str, resource_type: &str) -> &'a str {
    let prefix = format!("urn:ietf:params:scim:schemas:core:2.0:{resource_type}:");
    if path.len() >= prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(&prefix) {
        &path[prefix.len()..]
    } else {
        path
    }
}

fn invalid_value(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidValue)
}

pub(in crate::scim::axum) fn project_value(
    value: Value,
    projection: &AttributeProjection,
) -> Value {
    let (AttributeProjection::Include(paths) | AttributeProjection::Exclude(paths)) = projection
    else {
        return value;
    };
    let Some(resource) = value.as_object() else {
        return value;
    };
    let tree = PathNode::from_paths(paths, resource.keys().map(String::as_str));
    let mut output = serde_json::Map::new();
    for key in ["schemas", "id"] {
        if let Some(value) = resource.get(key) {
            output.insert(key.into(), value.clone());
        }
    }
    for (key, value) in resource {
        if matches!(key.as_str(), "schemas" | "id") {
            continue;
        }
        let node = tree.children.get(&key.to_ascii_lowercase());
        match projection {
            AttributeProjection::Include(_) => {
                if let Some(selected) = node.and_then(|node| include_value(value, node)) {
                    output.insert(key.clone(), selected);
                }
            }
            AttributeProjection::Exclude(_) => match node {
                Some(node) => {
                    if let Some(selected) = exclude_value(value, node) {
                        output.insert(key.clone(), selected);
                    }
                }
                None => {
                    output.insert(key.clone(), value.clone());
                }
            },
            AttributeProjection::Default => unreachable!(),
        }
    }
    Value::Object(output)
}

#[derive(Debug, Default)]
struct PathNode {
    selected: bool,
    children: HashMap<String, Self>,
}

impl PathNode {
    fn from_paths<'a>(paths: &HashSet<String>, root_names: impl Iterator<Item = &'a str>) -> Self {
        let mut root = Self::default();
        let mut root_names = root_names.collect::<Vec<_>>();
        root_names.sort_by_key(|name| std::cmp::Reverse(name.len()));
        for path in paths {
            let root_name = root_names.iter().find(|name| {
                let name = name.to_ascii_lowercase();
                path == &name || path.starts_with(&format!("{name}."))
            });
            let mut segments = Vec::new();
            let relative = if let Some(root_name) = root_name {
                segments.push(root_name.to_ascii_lowercase());
                path[root_name.len()..].strip_prefix('.').unwrap_or("")
            } else {
                path.as_str()
            };
            segments.extend(
                relative
                    .split('.')
                    .filter(|segment| !segment.is_empty())
                    .map(str::to_owned),
            );
            let mut node = &mut root;
            for segment in segments {
                node = node.children.entry(segment).or_default();
            }
            node.selected = true;
        }
        root
    }
}

fn include_value(value: &Value, node: &PathNode) -> Option<Value> {
    if node.selected {
        return Some(value.clone());
    }
    if let Some(values) = value.as_array() {
        let selected = values
            .iter()
            .filter_map(|value| include_value(value, node))
            .collect::<Vec<_>>();
        return (!selected.is_empty()).then_some(Value::Array(selected));
    }
    let object = value.as_object()?;
    let selected = object
        .iter()
        .filter_map(|(key, value)| {
            node.children
                .get(&key.to_ascii_lowercase())
                .and_then(|node| include_value(value, node))
                .map(|value| (key.clone(), value))
        })
        .collect::<serde_json::Map<_, _>>();
    (!selected.is_empty()).then_some(Value::Object(selected))
}

fn exclude_value(value: &Value, node: &PathNode) -> Option<Value> {
    if node.selected {
        return None;
    }
    if let Some(values) = value.as_array() {
        return Some(Value::Array(
            values
                .iter()
                .filter_map(|value| exclude_value(value, node))
                .collect(),
        ));
    }
    let Some(object) = value.as_object() else {
        return Some(value.clone());
    };
    Some(Value::Object(
        object
            .iter()
            .filter_map(
                |(key, value)| match node.children.get(&key.to_ascii_lowercase()) {
                    Some(node) => exclude_value(value, node).map(|value| (key.clone(), value)),
                    None => Some((key.clone(), value.clone())),
                },
            )
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn query(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    #[test]
    fn projection_rejects_conflicts_and_selects_nested_values() {
        let conflict = projection(
            &query(&[
                ("attributes", "userName"),
                ("excludedAttributes", "active"),
            ]),
            "User",
        )
        .unwrap_err();
        assert_eq!(conflict.scim_type, Some(ScimErrorType::InvalidValue));
        assert_eq!(
            conflict.detail,
            "attributes and excludedAttributes cannot be used together"
        );

        let projection = projection(
            &query(&[("attributes", "name.givenName,manager.value")]),
            "User",
        )
        .unwrap();
        let projected = project_value(
            json!({
                "schemas": ["core", SCIM_ENTERPRISE_USER_SCHEMA],
                "id": "user-1",
                "userName": "luna@example.com",
                "name": { "givenName": "Luna", "familyName": "Lake" },
                SCIM_ENTERPRISE_USER_SCHEMA: {
                    "department": "Engineering",
                    "manager": { "value": "manager-1", "displayName": "Manager" }
                }
            }),
            &projection,
        );
        assert_eq!(projected["id"], "user-1");
        assert_eq!(projected["name"], json!({ "givenName": "Luna" }));
        assert_eq!(
            projected[SCIM_ENTERPRISE_USER_SCHEMA],
            json!({ "manager": { "value": "manager-1" } })
        );
        assert!(projected.get("userName").is_none());
    }

    #[test]
    fn excluded_projection_preserves_required_and_other_nested_values() {
        let projection = projection(
            &query(&[(
                "excludedAttributes",
                "emails.type,name.familyName",
            )]),
            "User",
        )
        .unwrap();
        let projected = project_value(
            json!({
                "schemas": ["core"],
                "id": "user-1",
                "name": { "givenName": "Luna", "familyName": "Lake" },
                "emails": [{ "value": "luna@example.com", "type": "work" }]
            }),
            &projection,
        );
        assert_eq!(projected["schemas"], json!(["core"]));
        assert_eq!(projected["id"], "user-1");
        assert_eq!(projected["name"], json!({ "givenName": "Luna" }));
        assert_eq!(
            projected["emails"],
            json!([{ "value": "luna@example.com" }])
        );
    }
}
