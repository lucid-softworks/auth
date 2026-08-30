use super::{canonical_user_key, enforce_primary};
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
    let matches = values
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| selector_matches(entry, &path.selector).then_some(index))
        .collect::<Vec<_>>();
    if op == "remove" {
        remove(values, &matches, path.subattribute.as_deref());
        return Ok(());
    }
    let value = value.ok_or_else(|| {
        ScimError::typed(
            400,
            "PATCH value is required",
            ScimErrorType::InvalidValue,
        )
    })?;
    let preferred_primary = if matches.is_empty() {
        if key == "emails" && path.selector == FilterSelector::Primary(true) {
            return Err(ScimError::typed(
                400,
                "No primary email matches the PATCH path",
                ScimErrorType::NoTarget,
            ));
        }
        create(
            values,
            &path.selector,
            path.subattribute.as_deref(),
            value,
        )?
    } else {
        replace(
            values,
            &matches,
            path.subattribute.as_deref(),
            value,
        )?
    };
    if let Some(index) = preferred_primary {
        enforce_primary(values, index);
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

fn remove(values: &mut Vec<Value>, matches: &[usize], subattribute: Option<&str>) {
    if let Some(subattribute) = subattribute {
        for index in matches {
            if let Some(object) = values[*index].as_object_mut() {
                object.remove(subattribute);
            }
        }
    } else {
        let mut index = 0;
        values.retain(|_| {
            let keep = !matches.contains(&index);
            index += 1;
            keep
        });
    }
}

fn replace(
    values: &mut [Value],
    matches: &[usize],
    subattribute: Option<&str>,
    value: Value,
) -> Result<Option<usize>, ScimError> {
    if let Some(subattribute) = subattribute {
        for index in matches {
            values[*index]
                .as_object_mut()
                .ok_or_else(|| {
                    ScimError::typed(400, "Invalid PATCH target", ScimErrorType::InvalidPath)
                })?
                .insert(subattribute.into(), value.clone());
        }
        Ok((subattribute.eq_ignore_ascii_case("primary") && value == Value::Bool(true))
            .then_some(matches[0]))
    } else {
        let replacement = one_complex_value(value)?;
        for index in matches {
            values[*index]
                .as_object_mut()
                .ok_or_else(|| {
                    ScimError::typed(400, "Invalid PATCH target", ScimErrorType::InvalidPath)
                })?
                .extend(replacement.clone());
        }
        Ok((replacement.get("primary").and_then(Value::as_bool) == Some(true))
            .then_some(matches[0]))
    }
}

fn create(
    values: &mut Vec<Value>,
    selector: &FilterSelector,
    subattribute: Option<&str>,
    value: Value,
) -> Result<Option<usize>, ScimError> {
    if subattribute.is_none() {
        let additions = match value {
            Value::Array(values) => values,
            value => vec![value],
        };
        let start = values.len();
        let mut preferred_primary = None;
        for (offset, value) in additions.into_iter().enumerate() {
            let mut entry = one_complex_value(value)?;
            apply_selector(&mut entry, selector);
            if preferred_primary.is_none()
                && entry.get("primary").and_then(Value::as_bool) == Some(true)
            {
                preferred_primary = Some(start + offset);
            }
            values.push(Value::Object(entry));
        }
        return Ok(preferred_primary);
    }
    let mut entry = serde_json::Map::new();
    apply_selector(&mut entry, selector);
    if let Some(subattribute) = subattribute {
        entry.insert(subattribute.into(), value);
    }
    let index = values.len();
    let primary = entry.get("primary").and_then(Value::as_bool) == Some(true);
    values.push(Value::Object(entry));
    Ok(primary.then_some(index))
}

fn apply_selector(entry: &mut serde_json::Map<String, Value>, selector: &FilterSelector) {
    match selector {
        FilterSelector::Type(kind) => {
            entry.insert("type".into(), Value::String(kind.clone()));
        }
        FilterSelector::Primary(primary) => {
            entry.insert("primary".into(), Value::Bool(*primary));
        }
    }
}

fn one_complex_value(value: Value) -> Result<serde_json::Map<String, Value>, ScimError> {
    let value = match value {
        Value::Array(mut values) if values.len() == 1 => values.remove(0),
        value => value,
    };
    value.as_object().cloned().ok_or_else(|| {
        ScimError::typed(
            400,
            "Filtered PATCH path requires one complex value",
            ScimErrorType::InvalidValue,
        )
    })
}
