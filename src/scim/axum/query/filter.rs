use crate::scim::{ScimError, ScimErrorType};
use regex::Regex;
use serde_json::Value;
use std::{collections::HashMap, sync::OnceLock};

pub(in crate::scim::axum) fn filter(
    values: Vec<Value>,
    query: &HashMap<String, String>,
    resource_type: &str,
) -> Result<Vec<Value>, ScimError> {
    let Some(filter) = query.get("filter") else {
        return Ok(values);
    };
    if filter.trim().is_empty() {
        return Ok(values);
    }
    let expressions = split_and(filter)?
        .iter()
        .map(|expression| parse_expression(expression, resource_type))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(values
        .into_iter()
        .filter(|value| {
            expressions
                .iter()
                .all(|(path, expected)| matches_value(value, path, expected))
        })
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
            ']' if bracket_depth == 0 => {
                return Err(invalid_filter(
                    "filter contains malformed quotes or brackets",
                ));
            }
            ']' => bracket_depth -= 1,
            _ => {}
        }
        if bracket_depth == 0
            && index + 3 <= bytes.len()
            && filter[index..index + 3].eq_ignore_ascii_case("and")
            && index > 0
            && index + 3 < bytes.len()
            && bytes[index - 1].is_ascii_whitespace()
            && bytes[index + 3].is_ascii_whitespace()
        {
            let expression = filter[start..index].trim();
            if expression.is_empty() {
                return Err(invalid_filter("filter contains an invalid conjunction"));
            }
            output.push(expression.to_owned());
            start = index + 3;
            index += 3;
            continue;
        }
        index += 1;
    }
    if quoted || bracket_depth != 0 {
        return Err(invalid_filter(
            "filter contains malformed quotes or brackets",
        ));
    }
    let final_expression = filter[start..].trim();
    if final_expression.is_empty() {
        return Err(invalid_filter("filter contains an invalid conjunction"));
    }
    if output.len() >= 10 {
        return Err(invalid_filter(
            "filter supports at most 10 equality expressions",
        ));
    }
    output.push(final_expression.to_owned());
    Ok(output)
}

fn parse_expression(expression: &str, resource_type: &str) -> Result<(String, String), ScimError> {
    let Some((raw_path, operator, raw_value)) = find_operation(expression) else {
        return Err(invalid_filter(
            "filter must use the form attribute eq \"value\"",
        ));
    };
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(invalid_filter(format!(
            "filter operator {operator} is not supported"
        )));
    }
    let path = canonical_path(raw_path, resource_type).ok_or_else(|| {
        invalid_filter(format!(
            "filter attribute {raw_path} is not supported for {resource_type}"
        ))
    })?;
    let expected = serde_json::from_str::<Value>(raw_value).map_err(|_| {
        invalid_filter("filter equality value must be a valid quoted JSON string")
    })?;
    let expected = expected
        .as_str()
        .ok_or_else(|| invalid_filter("filter equality value must be a quoted string"))?;
    Ok((path, expected.to_owned()))
}

fn find_operation(expression: &str) -> Option<(&str, &str, &str)> {
    let bytes = expression.as_bytes();
    let mut quoted = false;
    let mut escaped = false;
    let mut bracket_depth = 0_u32;
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
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            _ if bracket_depth == 0 && character.is_ascii_alphabetic() => {
                let start = index;
                while index + 1 < bytes.len() && bytes[index + 1].is_ascii_alphabetic() {
                    index += 1;
                }
                let end = index + 1;
                if start > 0
                    && end < bytes.len()
                    && bytes[start - 1].is_ascii_whitespace()
                    && bytes[end].is_ascii_whitespace()
                {
                    let attribute = expression[..start].trim();
                    let value = expression[end..].trim();
                    if !attribute.is_empty() && !value.is_empty() {
                        return Some((attribute, &expression[start..end], value));
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn canonical_path(path: &str, resource_type: &str) -> Option<String> {
    let path = strip_core_prefix(path, resource_type);
    let lower = path.to_ascii_lowercase();
    match (resource_type, lower.as_str()) {
        (_, "id") => Some("id".into()),
        (_, "externalid") => Some("externalId".into()),
        ("User", "username") => Some("userName".into()),
        ("User", "emails.value") => Some("emails.value".into()),
        ("User", value) if work_email_path_regex().is_match(value) => {
            Some("emails.work.value".into())
        }
        ("Group", "displayname") => Some("displayName".into()),
        _ => None,
    }
}

fn strip_core_prefix<'a>(path: &'a str, resource_type: &str) -> &'a str {
    let prefix = format!("urn:ietf:params:scim:schemas:core:2.0:{resource_type}:");
    if path.len() >= prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(&prefix) {
        &path[prefix.len()..]
    } else {
        path
    }
}

fn work_email_path_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"^emails\[\s*type\s+eq\s+\"work\"\s*\]\.value$"#)
            .expect("the work email path regex is valid")
    })
}

fn matches_value(value: &Value, path: &str, expected: &str) -> bool {
    match path {
        "emails.value" => value["emails"].as_array().is_some_and(|emails| {
            emails
                .iter()
                .any(|email| email["value"].as_str() == Some(expected))
        }),
        "emails.work.value" => value["emails"].as_array().is_some_and(|emails| {
            emails.iter().any(|email| {
                email["type"]
                    .as_str()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("work"))
                    && email["value"].as_str() == Some(expected)
            })
        }),
        path => value.get(path).and_then(Value::as_str) == Some(expected),
    }
}

fn invalid_filter(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidFilter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn query(value: &str) -> HashMap<String, String> {
        HashMap::from([("filter".into(), value.into())])
    }

    #[test]
    fn filters_match_the_supported_conjunction_grammar() {
        let values = vec![json!({
            "id": "user-1",
            "userName": "luna@example.com",
            "emails": [{ "type": "work", "value": "luna@example.com" }]
        })];
        let filtered = filter(
            values.clone(),
            &query(
                "userName EQ \"luna@example.com\" AnD emails[type eq \"work\"].value eq \"luna@example.com\"",
            ),
            "User",
        )
        .unwrap();
        assert_eq!(filtered, values);

        let error = filter(values, &query("userName co \"luna\""), "User").unwrap_err();
        assert_eq!(error.scim_type, Some(ScimErrorType::InvalidFilter));
        assert_eq!(error.detail, "filter operator co is not supported");
    }
}
