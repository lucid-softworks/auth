use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SchemaError {
    path: String,
    expected: &'static str,
}

impl SchemaError {
    pub(super) fn new(path: impl Into<String>, expected: &'static str) -> Self {
        Self {
            path: path.into(),
            expected,
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Polar SDK response validation failed at {}: expected {}",
            self.path, self.expected
        )
    }
}

impl std::error::Error for SchemaError {}
