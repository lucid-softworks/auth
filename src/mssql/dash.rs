use super::{
    MssqlComparisonMode, MssqlFilter, MssqlFilterConnector, MssqlFilterOperator,
    MssqlFindOptions, MssqlSort, MssqlSortDirection, MssqlStore,
};
use crate::{
    AuthError, DashAdapterConnector, DashAdapterOperator, DashAdapterSort, DashAdapterWhere,
    DashSortDirection,
};
use serde_json::{Map, Value};

pub(super) async fn find(
    store: &MssqlStore,
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
            &MssqlFindOptions {
                select: select.to_vec(),
                sort: sort.map(|sort| MssqlSort {
                    field: sort.field.clone(),
                    direction: match sort.direction {
                        DashSortDirection::Asc => MssqlSortDirection::Ascending,
                        DashSortDirection::Desc => MssqlSortDirection::Descending,
                    },
                }),
                limit: limit.map(|limit| limit as u64),
                offset: Some(offset as u64),
                joins: Vec::new(),
            },
        )
        .await
}

pub(super) fn filters(where_clause: &[DashAdapterWhere]) -> Vec<MssqlFilter> {
    where_clause
        .iter()
        .map(|condition| MssqlFilter {
            field: condition.field.clone(),
            value: condition.value.clone(),
            operator: match condition.operator {
                DashAdapterOperator::Eq => MssqlFilterOperator::Eq,
                DashAdapterOperator::Ne => MssqlFilterOperator::Ne,
                DashAdapterOperator::Gt => MssqlFilterOperator::Gt,
                DashAdapterOperator::Gte => MssqlFilterOperator::Gte,
                DashAdapterOperator::Lt => MssqlFilterOperator::Lt,
                DashAdapterOperator::Lte => MssqlFilterOperator::Lte,
                DashAdapterOperator::In => MssqlFilterOperator::In,
                DashAdapterOperator::Contains => MssqlFilterOperator::Contains,
                DashAdapterOperator::StartsWith => MssqlFilterOperator::StartsWith,
                DashAdapterOperator::EndsWith => MssqlFilterOperator::EndsWith,
            },
            connector: match condition.connector.unwrap_or(DashAdapterConnector::And) {
                DashAdapterConnector::And => MssqlFilterConnector::And,
                DashAdapterConnector::Or => MssqlFilterConnector::Or,
            },
            mode: MssqlComparisonMode::Sensitive,
        })
        .collect()
}
