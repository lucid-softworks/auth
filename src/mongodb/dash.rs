use super::{
    MongoComparisonMode, MongoFilter, MongoFilterConnector, MongoFilterOperator,
    MongoFindOptions, MongoSort, MongoSortDirection, MongoStore,
};
use crate::{
    AuthError, DashAdapterConnector, DashAdapterOperator, DashAdapterSort, DashAdapterWhere,
    DashSortDirection,
};
use serde_json::{Map, Value};

pub(super) async fn find(
    store: &MongoStore,
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
            &MongoFindOptions {
                select: select.to_vec(),
                sort: sort.map(|sort| MongoSort {
                    field: sort.field.clone(),
                    direction: match sort.direction {
                        DashSortDirection::Asc => MongoSortDirection::Ascending,
                        DashSortDirection::Desc => MongoSortDirection::Descending,
                    },
                }),
                limit: limit.map(|limit| limit as u64),
                offset: Some(offset as u64),
                ..Default::default()
            },
        )
        .await
}

pub(super) fn filters(where_clause: &[DashAdapterWhere]) -> Vec<MongoFilter> {
    where_clause
        .iter()
        .map(|condition| MongoFilter {
            field: condition.field.clone(),
            value: condition.value.clone(),
            operator: match condition.operator {
                DashAdapterOperator::Eq => MongoFilterOperator::Eq,
                DashAdapterOperator::Ne => MongoFilterOperator::Ne,
                DashAdapterOperator::Gt => MongoFilterOperator::Gt,
                DashAdapterOperator::Gte => MongoFilterOperator::Gte,
                DashAdapterOperator::Lt => MongoFilterOperator::Lt,
                DashAdapterOperator::Lte => MongoFilterOperator::Lte,
                DashAdapterOperator::In => MongoFilterOperator::In,
                DashAdapterOperator::Contains => MongoFilterOperator::Contains,
                DashAdapterOperator::StartsWith => MongoFilterOperator::StartsWith,
                DashAdapterOperator::EndsWith => MongoFilterOperator::EndsWith,
            },
            connector: match condition.connector.unwrap_or(DashAdapterConnector::And) {
                DashAdapterConnector::And => MongoFilterConnector::And,
                DashAdapterConnector::Or => MongoFilterConnector::Or,
            },
            mode: MongoComparisonMode::Sensitive,
        })
        .collect()
}
