use super::{merge_object, required_value, set_enterprise_schema};
use crate::scim::{SCIM_ENTERPRISE_USER_SCHEMA, ScimError, ScimErrorType};
use serde_json::Value;

pub(super) fn apply(
    root: &mut Value,
    op: &str,
    path: &str,
    value: Option<Value>,
) -> Result<bool, ScimError> {
    if path.eq_ignore_ascii_case(SCIM_ENTERPRISE_USER_SCHEMA) {
        patch_enterprise_root(root, op, value)?;
        return Ok(true);
    }
    let lower = path.to_ascii_lowercase();
    let enterprise_prefix = format!("{}.", SCIM_ENTERPRISE_USER_SCHEMA.to_ascii_lowercase());
    let (container, relative) = if lower.starts_with(&enterprise_prefix) {
        (SCIM_ENTERPRISE_USER_SCHEMA, &path[enterprise_prefix.len()..])
    } else if lower.starts_with("name.") {
        ("name", &path[5..])
    } else {
        return Ok(false);
    };
    let key = canonical_key(container, relative).ok_or_else(|| {
        ScimError::typed(
            400,
            format!("User PATCH path {path} is not supported"),
            ScimErrorType::InvalidPath,
        )
    })?;
    let object = root.as_object_mut().expect("SCIM User is an object");
    if op == "remove" {
        if let Some(value) = object.get_mut(container).and_then(Value::as_object_mut) {
            value.remove(key);
            if value.is_empty() {
                object.remove(container);
                if container == SCIM_ENTERPRISE_USER_SCHEMA {
                    set_enterprise_schema(root, false);
                }
            }
        }
        return Ok(true);
    }
    let container_value = object
        .entry(container)
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let container_object = container_value.as_object_mut().ok_or_else(|| {
        ScimError::typed(
            400,
            format!("{container} must be an object"),
            ScimErrorType::InvalidValue,
        )
    })?;
    container_object.insert(key.into(), required_value(value)?);
    if container == SCIM_ENTERPRISE_USER_SCHEMA {
        set_enterprise_schema(root, true);
    }
    Ok(true)
}

fn canonical_key(container: &str, path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if container == "name" {
        return match lower.as_str() {
            "formatted" => Some("formatted"),
            "givenname" => Some("givenName"),
            "familyname" => Some("familyName"),
            "middlename" => Some("middleName"),
            "honorificprefix" => Some("honorificPrefix"),
            "honorificsuffix" => Some("honorificSuffix"),
            _ => None,
        };
    }
    match lower.as_str() {
        "employeenumber" => Some("employeeNumber"),
        "costcenter" => Some("costCenter"),
        "organization" => Some("organization"),
        "division" => Some("division"),
        "department" => Some("department"),
        "manager" => Some("manager"),
        _ => None,
    }
}

fn patch_enterprise_root(
    root: &mut Value,
    op: &str,
    value: Option<Value>,
) -> Result<(), ScimError> {
    if op == "remove" {
        root.as_object_mut()
            .unwrap()
            .remove(SCIM_ENTERPRISE_USER_SCHEMA);
        set_enterprise_schema(root, false);
        return Ok(());
    }
    let value = required_value(value)?;
    if !value.is_object() {
        return Err(ScimError::typed(
            400,
            format!("{SCIM_ENTERPRISE_USER_SCHEMA} must be an object"),
            ScimErrorType::InvalidValue,
        ));
    }
    merge_object(
        root.as_object_mut().unwrap(),
        SCIM_ENTERPRISE_USER_SCHEMA,
        value,
    )?;
    set_enterprise_schema(root, true);
    Ok(())
}
