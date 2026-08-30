use super::{
    SqliteComparisonMode, SqliteFilter, SqliteFilterConnector, SqliteFilterOperator,
    SqliteFindOptions, SqliteSort, SqliteSortDirection, SqliteStore,
};
use crate::{
    AuthError, DashAdapterConnector, DashAdapterOperator, DashAdapterSort, DashAdapterWhere,
    DashSortDirection,
};
use serde_json::{Map, Value};

pub(super) async fn find(
    store: &SqliteStore,
    model: &str,
    where_clause: &[DashAdapterWhere],
    limit: Option<usize>,
    offset: usize,
    sort: Option<&DashAdapterSort>,
    select: &[String],
) -> Result<Vec<Map<String, Value>>, AuthError> {
    store
        .find_records(
            model,
            &filters(where_clause),
            &SqliteFindOptions {
                select: select.to_vec(),
                sort: sort.map(|sort| SqliteSort {
                    field: sort.field.clone(),
                    direction: match sort.direction {
                        DashSortDirection::Asc => SqliteSortDirection::Ascending,
                        DashSortDirection::Desc => SqliteSortDirection::Descending,
                    },
                }),
                limit: limit.map(|limit| limit as u64),
                offset: Some(offset as u64),
            },
        )
        .await
}

pub(super) fn filters(where_clause: &[DashAdapterWhere]) -> Vec<SqliteFilter> {
    where_clause
        .iter()
        .map(|condition| SqliteFilter {
            field: condition.field.clone(),
            value: condition.value.clone(),
            operator: match condition.operator {
                DashAdapterOperator::Eq => SqliteFilterOperator::Eq,
                DashAdapterOperator::Ne => SqliteFilterOperator::Ne,
                DashAdapterOperator::Gt => SqliteFilterOperator::Gt,
                DashAdapterOperator::Gte => SqliteFilterOperator::Gte,
                DashAdapterOperator::Lt => SqliteFilterOperator::Lt,
                DashAdapterOperator::Lte => SqliteFilterOperator::Lte,
                DashAdapterOperator::In => SqliteFilterOperator::In,
                DashAdapterOperator::Contains => SqliteFilterOperator::Contains,
                DashAdapterOperator::StartsWith => SqliteFilterOperator::StartsWith,
                DashAdapterOperator::EndsWith => SqliteFilterOperator::EndsWith,
            },
            connector: match condition.connector.unwrap_or(DashAdapterConnector::And) {
                DashAdapterConnector::And => SqliteFilterConnector::And,
                DashAdapterConnector::Or => SqliteFilterConnector::Or,
            },
            mode: SqliteComparisonMode::Sensitive,
        })
        .collect()
}
