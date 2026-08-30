use crate::scim::{SCIM_ENTERPRISE_USER_SCHEMA, ScimError, ScimErrorType, ScimPatchRequest};
use serde_json::Value;

pub(super) fn apply(value: &mut Value, patch: &ScimPatchRequest) -> Result<(), ScimError> {
    for operation in &patch.operations {
        let op = operation.op.to_ascii_lowercase();
        if !matches!(op.as_str(), "add" | "replace" | "remove") {
            return Err(ScimError::typed(
                400,
                "PATCH operation must be add, replace, or remove",
                ScimErrorType::InvalidSyntax,
            ));
        }
        let path = operation
            .path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty());
        if path.is_none() {
            apply_pathless(value, &op, operation.value.as_ref())?;
            continue;
        }
        apply_path(value, &op, path.unwrap(), operation.value.clone())?;
    }
    Ok(())
}

fn apply_pathless(root: &mut Value, op: &str, value: Option<&Value>) -> Result<(), ScimError> {
    if op == "remove" {
        return Err(ScimError::typed(
            400,
            "Pathless remove has no target",
            ScimErrorType::NoTarget,
        ));
    }
    let additions = value.and_then(Value::as_object).ok_or_else(|| {
        ScimError::typed(
            400,
            "Pathless PATCH value must be an object",
            ScimErrorType::InvalidValue,
        )
    })?;
    for (key, value) in additions {
        apply_path(root, op, key, Some(value.clone()))?;
    }
    Ok(())
}

fn apply_path(
    root: &mut Value,
    op: &str,
    raw_path: &str,
    value: Option<Value>,
) -> Result<(), ScimError> {
    let path = normalize_user_path(raw_path);
    let lower = path.to_ascii_lowercase();
    if matches!(lower.as_str(), "id" | "meta" | "schemas") || lower.starts_with("meta.") {
        return Err(ScimError::typed(
            400,
            format!("{raw_path} is read-only"),
            ScimErrorType::Mutability,
        ));
    }
    if let Some((attribute, kind, subattribute)) = filtered_path(&path) {
        return patch_filtered_value(root, op, attribute, kind, subattribute, value);
    }
    if patch_nested(root, op, &path, value.clone())? {
        return Ok(());
    }
    patch_attribute(root, op, &path, value)
}

fn patch_attribute(
    root: &mut Value,
    op: &str,
    path: &str,
    value: Option<Value>,
) -> Result<(), ScimError> {
    let key = canonical_user_key(path).ok_or_else(|| {
        ScimError::typed(
            400,
            "Unsupported SCIM User PATCH path",
            ScimErrorType::InvalidPath,
        )
    })?;
    let object = root
        .as_object_mut()
        .expect("SCIM User serializes as an object");
    if op == "remove" {
        object.remove(key);
    } else {
        let value = required_value(value)?;
        if key == "name" && value.is_object() {
            merge_object(object, key, value)?;
        } else {
            object.insert(key.into(), value);
        }
    }
    Ok(())
}

fn normalize_user_path(path: &str) -> String {
    const CORE_PREFIX: &str = "urn:ietf:params:scim:schemas:core:2.0:User:";
    let path = path.trim();
    if path.len() >= CORE_PREFIX.len() && path[..CORE_PREFIX.len()].eq_ignore_ascii_case(CORE_PREFIX)
    {
        return path[CORE_PREFIX.len()..].to_owned();
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
    path.to_owned()
}

fn patch_nested(
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
    let key = canonical_nested_key(container, relative).ok_or_else(|| {
        ScimError::typed(
            400,
            format!("User PATCH path {path} is not supported"),
            ScimErrorType::InvalidPath,
        )
    })?;
    let object = root.as_object_mut().expect("SCIM User is an object");
    if op == "remove" {
        if let Some(container) = object.get_mut(container).and_then(Value::as_object_mut) {
            container.remove(key);
            if container.is_empty() {
                object.remove(container_key(path));
                set_enterprise_schema(root, false);
            }
        }
        return Ok(true);
    }
    let container_value = object
        .entry(container)
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let container_object = container_value.as_object_mut().ok_or_else(|| {
        ScimError::typed(400, format!("{container} must be an object"), ScimErrorType::InvalidValue)
    })?;
    container_object.insert(key.into(), required_value(value)?);
    if container == SCIM_ENTERPRISE_USER_SCHEMA {
        set_enterprise_schema(root, true);
    }
    Ok(true)
}

fn container_key(path: &str) -> &str {
    if path.starts_with(SCIM_ENTERPRISE_USER_SCHEMA) {
        SCIM_ENTERPRISE_USER_SCHEMA
    } else {
        "name"
    }
}

fn canonical_nested_key(container: &str, path: &str) -> Option<&'static str> {
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
        root.as_object_mut().unwrap().remove(SCIM_ENTERPRISE_USER_SCHEMA);
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

fn merge_object(
    root: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Value,
) -> Result<(), ScimError> {
    let additions = value.as_object().cloned().ok_or_else(|| {
        ScimError::typed(400, format!("{key} must be an object"), ScimErrorType::InvalidValue)
    })?;
    root.entry(key)
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            ScimError::typed(400, format!("{key} must be an object"), ScimErrorType::InvalidValue)
        })?
        .extend(additions);
    Ok(())
}

fn set_enterprise_schema(root: &mut Value, declared: bool) {
    let Some(schemas) = root.get_mut("schemas").and_then(Value::as_array_mut) else {
        return;
    };
    schemas.retain(|schema| schema.as_str() != Some(SCIM_ENTERPRISE_USER_SCHEMA));
    if declared {
        schemas.push(Value::String(SCIM_ENTERPRISE_USER_SCHEMA.into()));
    }
}

fn required_value(value: Option<Value>) -> Result<Value, ScimError> {
    value.ok_or_else(|| {
        ScimError::typed(
            400,
            "PATCH value is required",
            ScimErrorType::InvalidValue,
        )
    })
}

fn canonical_user_key(path: &str) -> Option<&'static str> {
    match path.to_ascii_lowercase().as_str() {
        "externalid" => Some("externalId"),
        "username" => Some("userName"),
        "displayname" => Some("displayName"),
        "name" => Some("name"),
        "emails" => Some("emails"),
        "title" => Some("title"),
        "usertype" => Some("userType"),
        "preferredlanguage" => Some("preferredLanguage"),
        "locale" => Some("locale"),
        "timezone" => Some("timezone"),
        "phonenumbers" => Some("phoneNumbers"),
        "addresses" => Some("addresses"),
        "roles" => Some("roles"),
        "entitlements" => Some("entitlements"),
        "active" => Some("active"),
        _ => None,
    }
}

fn filtered_path(path: &str) -> Option<(&str, &str, Option<&str>)> {
    let open = path.find('[')?;
    let close = path.find(']')?;
    let attribute = path[..open].trim();
    let filter = path[open + 1..close].trim();
    let (_, value) = filter
        .split_once(" eq ")
        .or_else(|| filter.split_once(" EQ "))?;
    let kind = value.trim().trim_matches('"');
    let subattribute = path[close + 1..]
        .strip_prefix('.')
        .filter(|value| !value.is_empty());
    Some((attribute, kind, subattribute))
}

fn patch_filtered_value(
    root: &mut Value,
    op: &str,
    attribute: &str,
    kind: &str,
    subattribute: Option<&str>,
    value: Option<Value>,
) -> Result<(), ScimError> {
    let key = canonical_user_key(attribute).ok_or_else(|| {
        ScimError::typed(
            400,
            "Unsupported filtered PATCH path",
            ScimErrorType::InvalidPath,
        )
    })?;
    let values = root
        .as_object_mut()
        .unwrap()
        .entry(key)
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| {
            ScimError::typed(
                400,
                "Filtered PATCH target is not multi-valued",
                ScimErrorType::InvalidPath,
            )
        })?;
    let index = values.iter().position(|entry| {
        entry
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case(kind))
    });
    if op == "remove" {
        remove_filtered(values, index, subattribute);
        return Ok(());
    }
    let value = value.ok_or_else(|| {
        ScimError::typed(
            400,
            "PATCH value is required",
            ScimErrorType::InvalidValue,
        )
    })?;
    match index {
        Some(index) => replace_filtered(values, index, subattribute, value),
        None => create_filtered(values, kind, subattribute, value),
    }
}

fn remove_filtered(values: &mut Vec<Value>, index: Option<usize>, subattribute: Option<&str>) {
    let Some(index) = index else { return };
    if let Some(subattribute) = subattribute {
        if let Some(object) = values[index].as_object_mut() {
            object.remove(subattribute);
        }
    } else {
        values.remove(index);
    }
}

fn replace_filtered(
    values: &mut [Value],
    index: usize,
    subattribute: Option<&str>,
    value: Value,
) -> Result<(), ScimError> {
    if let Some(subattribute) = subattribute {
        values[index]
            .as_object_mut()
            .ok_or_else(|| {
                ScimError::typed(400, "Invalid PATCH target", ScimErrorType::InvalidPath)
            })?
            .insert(subattribute.into(), value);
    } else {
        values[index] = value;
    }
    Ok(())
}

fn create_filtered(
    values: &mut Vec<Value>,
    kind: &str,
    subattribute: Option<&str>,
    value: Value,
) -> Result<(), ScimError> {
    let mut entry = serde_json::Map::new();
    entry.insert("type".into(), Value::String(kind.into()));
    if let Some(subattribute) = subattribute {
        entry.insert(subattribute.into(), value);
    } else if let Some(object) = value.as_object() {
        entry.extend(object.clone());
    } else {
        return Err(ScimError::typed(
            400,
            "Invalid PATCH value",
            ScimErrorType::InvalidValue,
        ));
    }
    values.push(Value::Object(entry));
    Ok(())
}
