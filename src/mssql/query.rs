mod predicate;
pub(in crate::mssql) mod execute;

use serde_json::Value;

/// One Better Auth adapter predicate using a logical schema field.
#[derive(Debug, Clone, PartialEq)]
pub struct MssqlFilter {
    pub field: String,
    pub value: Value,
    pub operator: MssqlFilterOperator,
    pub connector: MssqlFilterConnector,
    pub mode: MssqlComparisonMode,
}

impl MssqlFilter {
    pub fn equal(field: impl Into<String>, value: Value) -> Self {
        Self {
            field: field.into(),
            value,
            operator: MssqlFilterOperator::Eq,
            connector: MssqlFilterConnector::And,
            mode: MssqlComparisonMode::Sensitive,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MssqlFilterOperator {
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
pub enum MssqlFilterConnector {
    #[default]
    And,
    Or,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MssqlComparisonMode {
    #[default]
    Sensitive,
    Insensitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MssqlSort {
    pub field: String,
    pub direction: MssqlSortDirection,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MssqlSortDirection {
    #[default]
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MssqlFindOptions {
    pub select: Vec<String>,
    pub sort: Option<MssqlSort>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}
