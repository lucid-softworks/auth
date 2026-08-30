use super::canonical_user_key;
use crate::scim::{ScimError, ScimErrorType};
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterSelector {
    Type(String),
    Primary(bool),
}

pub(super) struct FilteredPath {
    attribute: String,
    selector: FilterSelector,
    subattribute: Option<String>,
}

pub(super) fn parse(path: &str) -> Option<FilteredPath> {
    let open = path.find('[')?;
    let close = path.find(']')?;
    let attribute = path[..open].trim().to_owned();
    let captures = selector_regex().captures(path[open + 1..close].trim())?;
    let selector = if captures.get(1).is_some() {
        FilterSelector::Type(captures.get(2)?.as_str().to_ascii_lowercase())
    } else if captures.get(3).is_some() {
        FilterSelector::Primary(captures.get(4)?.as_str().eq_ignore_ascii_case("true"))
    } else {
        return None;
    };
    let subattribute = match path[close + 1..]
        .strip_prefix('.')
        .filter(|value| !value.is_empty())
    {
        Some(value) => Some(canonical_subattribute(value)?),
        None => None,
    };
    Some(FilteredPath {
        attribute,
        selector,
        subattribute,
    })
}

fn selector_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)^\s*(?:(type)\s+eq\s+\"([^\"]+)\"|(primary)\s+eq\s+\"?(true|false)\"?)\s*$"#)
            .expect("the User PATCH selector regex is valid")
    })
}

fn canonical_subattribute(value: &str) -> Option<String> {
    match value.to_ascii_lowercase().as_str() {
        "value" => Some("value".into()),
        "type" => Some("type".into()),
        "primary" => Some("primary".into()),
        "display" => Some("display".into()),
        _ => None,
    }
}

pub(super) fn apply(
    root: &mut Value,
    op: &str,
    path: FilteredPath,
    value: Option<Value>,
) -> Result<(), ScimError> {
    let key = canonical_user_key(&path.attribute).ok_or_else(|| {
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
    let index = values
        .iter()
        .position(|entry| selector_matches(entry, &path.selector));
    if op == "remove" {
        remove(values, index, path.subattribute.as_deref());
        return Ok(());
    }
    let value = value.ok_or_else(|| {
        ScimError::typed(
            400,
            "PATCH value is required",
            ScimErrorType::InvalidValue,
        )
    })?;
    let changed_index = match index {
        Some(index) => {
            replace(values, index, path.subattribute.as_deref(), value)?;
            index
        }
        None if key == "emails" && path.selector == FilterSelector::Primary(true) => {
            return Err(ScimError::typed(
                400,
                "No primary email matches the PATCH path",
                ScimErrorType::NoTarget,
            ));
        }
        None => create(
            values,
            &path.selector,
            path.subattribute.as_deref(),
            value,
        )?,
    };
    if values
        .get(changed_index)
        .and_then(|entry| entry.get("primary"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        enforce_primary(values, changed_index);
    }
    Ok(())
}

fn selector_matches(entry: &Value, selector: &FilterSelector) -> bool {
    match selector {
        FilterSelector::Type(kind) => entry
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case(kind)),
        FilterSelector::Primary(primary) => {
            entry.get("primary").and_then(Value::as_bool) == Some(*primary)
        }
    }
}

fn remove(values: &mut Vec<Value>, index: Option<usize>, subattribute: Option<&str>) {
    let Some(index) = index else { return };
    if let Some(subattribute) = subattribute {
        if let Some(object) = values[index].as_object_mut() {
            object.remove(subattribute);
        }
    } else {
        values.remove(index);
    }
}

fn replace(
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

fn create(
    values: &mut Vec<Value>,
    selector: &FilterSelector,
    subattribute: Option<&str>,
    value: Value,
) -> Result<usize, ScimError> {
    let mut entry = serde_json::Map::new();
    match selector {
        FilterSelector::Type(kind) => {
            entry.insert("type".into(), Value::String(kind.clone()));
        }
        FilterSelector::Primary(primary) => {
            entry.insert("primary".into(), Value::Bool(*primary));
        }
    }
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
    let index = values.len();
    values.push(Value::Object(entry));
    Ok(index)
}

fn enforce_primary(values: &mut [Value], selected: usize) {
    for (index, value) in values.iter_mut().enumerate() {
        if index == selected {
            continue;
        }
        if let Some(value) = value.as_object_mut()
            && value.get("primary").and_then(Value::as_bool) == Some(true)
        {
            value.insert("primary".into(), Value::Bool(false));
        }
    }
}
