use super::{
    MySqlComparisonMode, MySqlFilter, MySqlFilterConnector, MySqlFilterOperator,
    MySqlFindOptions, MySqlSort, MySqlSortDirection, MySqlStore,
};
use crate::{
    AuthError, DashAdapterConnector, DashAdapterOperator, DashAdapterSort, DashAdapterWhere,
    DashSortDirection,
};
use serde_json::{Map, Value};

pub(super) async fn find(
    store: &MySqlStore,
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
            &MySqlFindOptions {
                select: select.to_vec(),
                sort: sort.map(|sort| MySqlSort {
                    field: sort.field.clone(),
                    direction: match sort.direction {
                        DashSortDirection::Asc => MySqlSortDirection::Ascending,
                        DashSortDirection::Desc => MySqlSortDirection::Descending,
                    },
                }),
                limit: limit.map(|limit| limit as u64),
                offset: Some(offset as u64),
            },
        )
        .await
}

pub(super) fn filters(where_clause: &[DashAdapterWhere]) -> Vec<MySqlFilter> {
    where_clause
        .iter()
        .map(|condition| MySqlFilter {
            field: condition.field.clone(),
            value: condition.value.clone(),
            operator: match condition.operator {
                DashAdapterOperator::Eq => MySqlFilterOperator::Eq,
                DashAdapterOperator::Ne => MySqlFilterOperator::Ne,
                DashAdapterOperator::Gt => MySqlFilterOperator::Gt,
                DashAdapterOperator::Gte => MySqlFilterOperator::Gte,
                DashAdapterOperator::Lt => MySqlFilterOperator::Lt,
                DashAdapterOperator::Lte => MySqlFilterOperator::Lte,
                DashAdapterOperator::In => MySqlFilterOperator::In,
                DashAdapterOperator::Contains => MySqlFilterOperator::Contains,
                DashAdapterOperator::StartsWith => MySqlFilterOperator::StartsWith,
                DashAdapterOperator::EndsWith => MySqlFilterOperator::EndsWith,
            },
            connector: match condition.connector.unwrap_or(DashAdapterConnector::And) {
                DashAdapterConnector::And => MySqlFilterConnector::And,
                DashAdapterConnector::Or => MySqlFilterConnector::Or,
            },
            mode: MySqlComparisonMode::Sensitive,
        })
        .collect()
}
