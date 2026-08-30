use crate::scim::{ScimError, ScimErrorType};
use regex::Regex;
use serde_json::Value;
use std::{collections::{HashMap, HashSet}, sync::OnceLock};

#[derive(Debug, Clone, Copy)]
pub(super) struct Pagination {
    pub start_index: usize,
    pub offset: usize,
    pub count: usize,
}

pub(super) fn pagination(query: &HashMap<String, String>) -> Result<Pagination, ScimError> {
    let start = integer(query.get("startIndex"), "startIndex")?.unwrap_or(1).max(1) as usize;
    let count = integer(query.get("count"), "count")?.unwrap_or(100).clamp(0, 100) as usize;
    Ok(Pagination {
        start_index: start,
        offset: start - 1,
        count,
    })
}

fn integer(value: Option<&String>, name: &str) -> Result<Option<i64>, ScimError> {
    let Some(value) = value else {
        return Ok(None);
    };
    value.trim().parse::<i64>().map(Some).map_err(|_| {
        ScimError::typed(
            400,
            format!("{name} must be an integer"),
            ScimErrorType::InvalidValue,
        )
    })
}

pub(super) fn filter(
    values: Vec<Value>,
    query: &HashMap<String, String>,
    resource_type: &str,
) -> Result<Vec<Value>, ScimError> {
    let Some(filter) = query.get("filter") else {
        return Ok(values);
    };
    let expressions = split_and(filter)?;
    if expressions.is_empty() || expressions.len() > 10 {
        return Err(invalid_filter(if expressions.len() > 10 {
            "SCIM filters support at most 10 equality expressions"
        } else {
            "SCIM filter must contain an equality expression"
        }));
    }
    let expressions = expressions
        .iter()
        .map(|expression| parse_expression(expression, resource_type))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(values
        .into_iter()
        .filter(|value| expressions.iter().all(|(path, expected)| matches_value(value, path, expected)))
        .collect())
}

fn split_and(filter: &str) -> Result<Vec<String>, ScimError> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut bracket_depth = 0_i32;
    let bytes = filter.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let character = bytes[index] as char;
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            index += 1;
            continue;
        }
        match character {
            '"' => quoted = true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth -= 1,
            _ => {}
        }
        if bracket_depth < 0 {
            return Err(invalid_filter("SCIM filter contains an unmatched bracket"));
        }
        if bracket_depth == 0
            && index + 3 <= bytes.len()
            && filter[index..index + 3].eq_ignore_ascii_case("and")
            && (index == 0 || bytes[index - 1].is_ascii_whitespace())
            && (index + 3 == bytes.len() || bytes[index + 3].is_ascii_whitespace())
        {
            output.push(filter[start..index].trim().to_owned());
            start = index + 3;
            index += 3;
            continue;
        }
        index += 1;
    }
    if quoted || bracket_depth != 0 {
        return Err(invalid_filter("SCIM filter contains an unterminated value"));
    }
    output.push(filter[start..].trim().to_owned());
    Ok(output)
}

fn expression_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)^\s*([^\s]+(?:\s*\[\s*type\s+eq\s+\"work\"\s*\]\.value)?)\s+eq\s+(\"(?:\\.|[^\"])*\")\s*$"#)
            .expect("the SCIM filter regex is valid")
    })
}

fn parse_expression(expression: &str, resource_type: &str) -> Result<(String, String), ScimError> {
    let Some(captures) = expression_regex().captures(expression) else {
        return Err(invalid_filter(
            "Only equality expressions joined by and are supported",
        ));
    };
    let raw_path = captures.get(1).unwrap().as_str();
    let expected = serde_json::from_str::<String>(captures.get(2).unwrap().as_str())
        .map_err(|_| invalid_filter("SCIM filter contains an invalid JSON string"))?;
    let path = canonical_path(raw_path, resource_type)
        .ok_or_else(|| invalid_filter("The requested SCIM filter attribute is not supported"))?;
    Ok((path, expected))
}

fn canonical_path(path: &str, resource_type: &str) -> Option<String> {
    let path = path
        .strip_prefix("urn:ietf:params:scim:schemas:core:2.0:User:")
        .or_else(|| path.strip_prefix("urn:ietf:params:scim:schemas:core:2.0:Group:"))
        .unwrap_or(path);
    let lower = path.to_ascii_lowercase();
    match (resource_type, lower.as_str()) {
        (_, "id") => Some("id".into()),
        (_, "externalid") => Some("externalId".into()),
        ("User", "username") => Some("userName".into()),
        ("User", "emails.value") => Some("emails.value".into()),
        ("User", value) if value.starts_with("emails[") && value.ends_with("].value") => {
            Some("emails.work.value".into())
        }
        ("Group", "displayname") => Some("displayName".into()),
        _ => None,
    }
}

fn matches_value(value: &Value, path: &str, expected: &str) -> bool {
    match path {
        "emails.value" => value["emails"].as_array().is_some_and(|emails| {
            emails.iter().any(|email| email["value"].as_str() == Some(expected))
        }),
        "emails.work.value" => value["emails"].as_array().is_some_and(|emails| {
            emails.iter().any(|email| {
                email["type"].as_str().is_some_and(|kind| kind.eq_ignore_ascii_case("work"))
                    && email["value"].as_str() == Some(expected)
            })
        }),
        path => value.get(path).and_then(Value::as_str) == Some(expected),
    }
}

fn invalid_filter(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidFilter)
}

pub(super) fn project_value(mut value: Value, query: &HashMap<String, String>) -> Value {
    let attributes = paths(query.get("attributes"));
    let excluded = paths(query.get("excludedAttributes"));
    if !attributes.is_empty() && !excluded.is_empty() {
        return value;
    }
    let Some(object) = value.as_object_mut() else {
        return value;
    };
    if !attributes.is_empty() {
        let retained = attributes
            .iter()
            .map(|path| path.split('.').next().unwrap_or(path).to_ascii_lowercase())
            .chain(["schemas".into(), "id".into()])
            .collect::<HashSet<_>>();
        object.retain(|key, _| retained.contains(&key.to_ascii_lowercase()));
    } else if !excluded.is_empty() {
        let excluded = excluded
            .iter()
            .map(|path| path.split('.').next().unwrap_or(path).to_ascii_lowercase())
            .collect::<HashSet<_>>();
        object.retain(|key, _| {
            matches!(key.as_str(), "schemas" | "id")
                || !excluded.contains(&key.to_ascii_lowercase())
        });
    }
    value
}

fn paths(value: Option<&String>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) fn page(
    values: Vec<Value>,
    pagination: Pagination,
) -> (usize, Vec<Value>) {
    let total = values.len();
    let page = values
        .into_iter()
        .skip(pagination.offset)
        .take(pagination.count)
        .collect();
    (total, page)
}
