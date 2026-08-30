use crate::scim::{SCIM_ENTERPRISE_USER_SCHEMA, ScimError, ScimErrorType, ScimPatchRequest};
use serde_json::Value;

mod nested;

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
    if nested::apply(root, op, &path, value.clone())? {
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
        match key {
            "userName" => {
                return Err(ScimError::typed(
                    400,
                    "userName is read-only",
                    ScimErrorType::Mutability,
                ));
            }
            "active" => {
                object.insert(key.into(), Value::Bool(true));
            }
            "emails" => {
                return Err(ScimError::typed(
                    400,
                    "emails cannot be removed",
                    ScimErrorType::InvalidValue,
                ));
            }
            _ => {
                object.remove(key);
            }
        }
    } else {
        let value = if matches!(key, "userName" | "externalId" | "displayName") {
            Value::String(string_value(value, key)?)
        } else {
            required_value(value)?
        };
        if key == "name" && value.is_object() {
            merge_object(object, key, value)?;
        } else {
            object.insert(key.into(), value);
        }
    }
    Ok(())
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
        .ok_or_else(|| {
            ScimError::typed(
                400,
                format!("{attribute} must be a non-empty string"),
                ScimErrorType::InvalidValue,
            )
        })
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
