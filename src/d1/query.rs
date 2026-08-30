mod builder;
pub(super) mod execute;
mod predicate;

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct D1Filter {
    pub field: String,
    pub value: Value,
    pub operator: D1FilterOperator,
    pub connector: D1FilterConnector,
    pub mode: D1ComparisonMode,
}

impl D1Filter {
    pub fn equal(field: impl Into<String>, value: Value) -> Self {
        Self {
            field: field.into(),
            value,
            operator: D1FilterOperator::Eq,
            connector: D1FilterConnector::And,
            mode: D1ComparisonMode::Sensitive,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum D1FilterOperator {
    #[default]
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum D1FilterConnector {
    #[default]
    And,
    Or,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum D1ComparisonMode {
    #[default]
    Sensitive,
    Insensitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D1Sort {
    pub field: String,
    pub direction: D1SortDirection,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum D1SortDirection {
    #[default]
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct D1FindOptions {
    pub select: Vec<String>,
    pub sort: Option<D1Sort>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}
