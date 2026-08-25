use serde_json::{Value, json};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Issue {
    InvalidType {
        expected: &'static str,
        format: Option<&'static str>,
        received: &'static str,
    },
    InvalidValue {
        values: Vec<Value>,
    },
    InvalidUnion {
        errors: Vec<SchemaError>,
    },
    Custom {
        expected: &'static str,
        received: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SchemaError {
    path: String,
    issue: Issue,
}

impl SchemaError {
    pub(super) fn new(path: impl Into<String>, expected: &'static str) -> Self {
        Self::custom(path, expected, "unknown")
    }

    pub(super) fn invalid_type(
        path: impl Into<String>,
        expected: &'static str,
        received: &'static str,
    ) -> Self {
        let (expected, format) = if expected == "safeint" {
            ("int", Some("safeint"))
        } else {
            (expected, None)
        };
        Self {
            path: path.into(),
            issue: Issue::InvalidType {
                expected,
                format,
                received,
            },
        }
    }

    pub(super) fn invalid_value(path: impl Into<String>, values: Vec<Value>) -> Self {
        Self {
            path: path.into(),
            issue: Issue::InvalidValue { values },
        }
    }

    pub(super) fn invalid_union(path: impl Into<String>, errors: Vec<Self>) -> Self {
        Self {
            path: path.into(),
            issue: Issue::InvalidUnion { errors },
        }
    }

    pub(super) fn custom(
        path: impl Into<String>,
        expected: &'static str,
        received: &'static str,
    ) -> Self {
        Self {
            path: path.into(),
            issue: Issue::Custom { expected, received },
        }
    }

    /// Better Call's one-line validation message for the failing field.
    #[cfg(any(feature = "axum", test))]
    pub(crate) fn public_message(&self) -> String {
        let path = self.path.strip_prefix("$.").unwrap_or(&self.path);
        let location = if path == "$" {
            "body".to_owned()
        } else {
            format!("body.{path}")
        };
        match &self.issue {
            Issue::InvalidType {
                expected, received, ..
            } => format!("[{location}] Invalid input: expected {expected}, received {received}"),
            Issue::InvalidValue { values } => {
                let values = values
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("|");
                format!("[{location}] Invalid option: expected one of {values}")
            }
            Issue::InvalidUnion { .. } => format!("[{location}] Invalid input"),
            Issue::Custom { expected, received } => {
                format!("[{location}] Invalid input: expected {expected}, received {received}")
            }
        }
    }

    fn sdk_issue(&self, base_path: &str) -> Value {
        let relative_path = self.path.strip_prefix(base_path).unwrap_or(&self.path);
        let path = path_segments(relative_path);
        match &self.issue {
            Issue::InvalidType {
                expected,
                format,
                received,
            } => {
                let mut issue = serde_json::Map::new();
                issue.insert("expected".to_owned(), json!(expected));
                if let Some(format) = format {
                    issue.insert("format".to_owned(), json!(format));
                }
                issue.insert("code".to_owned(), json!("invalid_type"));
                issue.insert("path".to_owned(), Value::Array(path));
                issue.insert(
                    "message".to_owned(),
                    json!(format!(
                        "Invalid input: expected {expected}, received {received}"
                    )),
                );
                Value::Object(issue)
            }
            Issue::InvalidValue { values } => json!({
                "code": "invalid_value",
                "values": values,
                "path": path,
                "message": "Invalid input"
            }),
            Issue::InvalidUnion { errors } => json!({
                "code": "invalid_union",
                "errors": errors
                    .iter()
                    .map(|error| vec![error.sdk_issue(&self.path)])
                    .collect::<Vec<_>>(),
                "path": path,
                "message": "Invalid input"
            }),
            Issue::Custom { expected, .. } => json!({
                "code": "custom",
                "path": path,
                "message": format!("Invalid input: expected {expected}")
            }),
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let issues = Value::Array(vec![self.sdk_issue("$")]);
        write!(
            formatter,
            "{}",
            serde_json::to_string_pretty(&issues).expect("a schema issue is JSON")
        )
    }
}

impl std::error::Error for SchemaError {}

fn path_segments(path: &str) -> Vec<Value> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = path.strip_prefix('$').unwrap_or(path).chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '.' => {
                if !current.is_empty() {
                    segments.push(Value::String(std::mem::take(&mut current)));
                }
            }
            '[' => {
                if !current.is_empty() {
                    segments.push(Value::String(std::mem::take(&mut current)));
                }
                let mut index = String::new();
                for character in chars.by_ref() {
                    if character == ']' {
                        break;
                    }
                    index.push(character);
                }
                if let Ok(index) = index.parse::<u64>() {
                    segments.push(json!(index));
                }
            }
            character => current.push(character),
        }
    }
    if !current.is_empty() {
        segments.push(Value::String(current));
    }
    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_better_call_and_sdk_zod_shapes() {
        let error = SchemaError::invalid_type("$.plans[0].planId", "string", "undefined");
        assert_eq!(
            error.public_message(),
            "[body.plans[0].planId] Invalid input: expected string, received undefined"
        );
        assert_eq!(
            error.to_string(),
            "[\n  {\n    \"expected\": \"string\",\n    \"code\": \"invalid_type\",\n    \"path\": [\n      \"plans\",\n      0,\n      \"planId\"\n    ],\n    \"message\": \"Invalid input: expected string, received undefined\"\n  }\n]"
        );
    }
}
