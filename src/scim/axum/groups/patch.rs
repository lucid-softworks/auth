use crate::scim::{
    SCIM_GROUP_SCHEMA, ScimError, ScimErrorType, ScimGroup, ScimGroupMember, ScimPatchRequest,
};
use regex::Regex;
use serde_json::Value;
use std::{collections::HashSet, sync::OnceLock};

pub(in crate::scim::axum) fn apply(
    resource: &mut ScimGroup,
    patch: ScimPatchRequest,
) -> Result<(), ScimError> {
    for operation in patch.operations {
        let op = operation.op.to_ascii_lowercase();
        if !matches!(op.as_str(), "add" | "replace" | "remove") {
            return Err(ScimError::typed(
                400,
                "Invalid PATCH operation",
                ScimErrorType::InvalidSyntax,
            ));
        }
        let path = operation
            .path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty());
        let Some(path) = path else {
            apply_pathless(resource, &op, operation.value)?;
            continue;
        };
        let path = normalize_path(path);
        if path.eq_ignore_ascii_case("members") {
            apply_members(resource, &op, operation.value)?;
            continue;
        }
        if let Some(member_id) = filtered_member_id(path) {
            if op != "remove" {
                return Err(invalid_path("Unsupported Group PATCH path"));
            }
            resource.members.retain(|member| member.value != member_id);
            continue;
        }
        apply_attribute(resource, &op, path, operation.value)?;
    }
    resource.schemas = vec![SCIM_GROUP_SCHEMA.into()];
    Ok(())
}

fn apply_pathless(
    resource: &mut ScimGroup,
    op: &str,
    value: Option<Value>,
) -> Result<(), ScimError> {
    if op == "remove" {
        return Err(ScimError::typed(
            400,
            "A pathless remove operation has no target",
            ScimErrorType::NoTarget,
        ));
    }
    let values = value
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| invalid_value("A pathless Group PATCH value must be an object"))?;
    for (attribute, value) in values {
        match attribute.to_ascii_lowercase().as_str() {
            "id" => {
                if value.as_str() != resource.id.as_deref() {
                    return Err(mutability("A Group PATCH cannot change id"));
                }
            }
            "schemas" | "meta" => {}
            "members" => apply_members(resource, op, Some(value))?,
            _ => apply_attribute(resource, op, &attribute, Some(value))?,
        }
    }
    Ok(())
}

fn apply_attribute(
    resource: &mut ScimGroup,
    op: &str,
    path: &str,
    value: Option<Value>,
) -> Result<(), ScimError> {
    let lower = path.to_ascii_lowercase();
    if matches!(lower.as_str(), "id" | "schemas" | "meta") || lower.starts_with("meta.") {
        return Err(mutability(format!("{path} is read-only")));
    }
    match lower.as_str() {
        "displayname" if op == "remove" => Err(mutability(
            "displayName is required and cannot be removed",
        )),
        "displayname" => {
            resource.display_name = string_value(value, "displayName")?;
            Ok(())
        }
        "externalid" if op == "remove" => {
            resource.external_id = None;
            Ok(())
        }
        "externalid" => {
            resource.external_id = Some(string_value(value, "externalId")?);
            Ok(())
        }
        _ => Err(invalid_path("Unsupported Group PATCH path")),
    }
}

fn apply_members(
    resource: &mut ScimGroup,
    op: &str,
    value: Option<Value>,
) -> Result<(), ScimError> {
    if op == "remove" && value.is_none() {
        resource.members.clear();
        return Ok(());
    }
    let members = member_values(value)?;
    match op {
        "add" => resource.members.extend(members),
        "replace" => resource.members = members,
        "remove" => {
            let removed = members
                .into_iter()
                .map(|member| member.value)
                .collect::<HashSet<_>>();
            resource
                .members
                .retain(|member| !removed.contains(&member.value));
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn member_values(value: Option<Value>) -> Result<Vec<ScimGroupMember>, ScimError> {
    let values = value
        .and_then(|value| value.as_array().cloned())
        .ok_or_else(|| invalid_value("members must be an array"))?;
    if values.len() > 1000 {
        return Err(invalid_value(
            "Groups cannot contain more than 1000 direct members",
        ));
    }
    values
        .into_iter()
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|_| invalid_value("Group members must reference a SCIM User"))
        })
        .collect()
}

fn filtered_member_id(path: &str) -> Option<String> {
    let capture = member_path_regex().captures(path)?.get(1)?.as_str();
    serde_json::from_str::<String>(capture)
        .ok()
        .filter(|value| !value.is_empty())
}

fn member_path_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)^members\[\s*value\s+eq\s+(\"(?:\\.|[^\"])*\")\s*\]$"#)
            .expect("the Group member path regex is valid")
    })
}

fn normalize_path(path: &str) -> &str {
    const PREFIX: &str = "urn:ietf:params:scim:schemas:core:2.0:Group:";
    if path.len() >= PREFIX.len() && path[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        &path[PREFIX.len()..]
    } else {
        path
    }
}

fn string_value(value: Option<Value>, attribute: &str) -> Result<String, ScimError> {
    let value = match value {
        Some(Value::Array(mut values)) if values.len() == 1 => values.remove(0),
        Some(value) => value,
        None => Value::Null,
    };
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_value(format!("{attribute} must be a non-empty string")))
}

fn invalid_value(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidValue)
}

fn invalid_path(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidPath)
}

fn mutability(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::Mutability)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim::{SCIM_PATCH_SCHEMA, ScimPatchOperation};
    use serde_json::json;

    fn resource() -> ScimGroup {
        ScimGroup {
            schemas: vec![SCIM_GROUP_SCHEMA.into()],
            id: Some("group-1".into()),
            external_id: Some("external-1".into()),
            display_name: "Engineering".into(),
            members: ["user-1", "user-2"]
                .into_iter()
                .map(|value| ScimGroupMember {
                    value: value.into(),
                    reference: None,
                    display: None,
                    kind: Some("User".into()),
                })
                .collect(),
            meta: None,
        }
    }

    fn patch(operations: Vec<ScimPatchOperation>) -> ScimPatchRequest {
        ScimPatchRequest {
            schemas: vec![SCIM_PATCH_SCHEMA.into()],
            operations,
        }
    }

    #[test]
    fn member_operations_apply_in_order_and_remove_only_targets() {
        let mut group = resource();
        apply(
            &mut group,
            patch(vec![
                ScimPatchOperation {
                    op: "remove".into(),
                    path: Some("members".into()),
                    value: Some(json!([{ "value": "user-1" }])),
                },
                ScimPatchOperation {
                    op: "add".into(),
                    path: Some("members".into()),
                    value: Some(json!([{ "value": "user-3" }])),
                },
            ]),
        )
        .unwrap();
        assert_eq!(
            group
                .members
                .iter()
                .map(|member| member.value.as_str())
                .collect::<Vec<_>>(),
            ["user-2", "user-3"]
        );
    }

    #[test]
    fn pathless_and_core_qualified_attributes_match_the_package() {
        let mut group = resource();
        apply(
            &mut group,
            patch(vec![
                ScimPatchOperation {
                    op: "replace".into(),
                    path: None,
                    value: Some(json!({ "id": "group-1", "displayName": [" Platform "] })),
                },
                ScimPatchOperation {
                    op: "remove".into(),
                    path: Some(format!("{SCIM_GROUP_SCHEMA}:externalId")),
                    value: None,
                },
            ]),
        )
        .unwrap();
        assert_eq!(group.display_name, "Platform");
        assert_eq!(group.external_id, None);
    }
}
