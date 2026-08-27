use super::codec;
use crate::{
    AgentApprovalRequest, AgentCapabilityGrant, AgentHost, AgentIdentity, AuthError,
    sqlite::{SqliteFilter, SqliteFindOptions, SqliteSort, SqliteSortDirection, SqliteStore},
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

pub(super) async fn find<T>(
    store: &SqliteStore,
    model: &str,
    field: &str,
    value: &str,
    decode: fn(Map<String, Value>) -> Result<T, AuthError>,
) -> Result<Option<T>, AuthError> {
    store
        .find_record(model, &[eq(field, value)], &[])
        .await?
        .map(decode)
        .transpose()
}

pub(super) async fn list<T: AgentRecordOrder>(
    store: &SqliteStore,
    model: &str,
    field: &str,
    value: &str,
    decode: fn(Map<String, Value>) -> Result<T, AuthError>,
) -> Result<Vec<T>, AuthError> {
    let values = store
        .find_records(model, &[eq(field, value)], &SqliteFindOptions::default())
        .await?
        .into_iter()
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(order(values))
}

pub(super) async fn list_pending(
    store: &SqliteStore,
    field: &str,
    value: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    let values = store
        .find_records(
            "approvalRequest",
            &[eq(field, value), eq("status", "pending")],
            &SqliteFindOptions::default(),
        )
        .await?
        .into_iter()
        .map(codec::decode_approval)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(order(values))
}

pub(super) fn first_by_id() -> SqliteFindOptions {
    SqliteFindOptions {
        sort: Some(SqliteSort {
            field: "id".into(),
            direction: SqliteSortDirection::Ascending,
        }),
        limit: Some(1),
        ..Default::default()
    }
}

pub(super) trait AgentRecordOrder {
    fn created_at(&self) -> DateTime<Utc>;
    fn id(&self) -> &str;
}

macro_rules! ordered_record {
    ($record:ty) => {
        impl AgentRecordOrder for $record {
            fn created_at(&self) -> DateTime<Utc> {
                self.created_at
            }

            fn id(&self) -> &str {
                &self.id
            }
        }
    };
}

ordered_record!(AgentHost);
ordered_record!(AgentIdentity);
ordered_record!(AgentCapabilityGrant);
ordered_record!(AgentApprovalRequest);

fn order<T: AgentRecordOrder>(mut values: Vec<T>) -> Vec<T> {
    values.sort_by(|left, right| {
        left.created_at()
            .cmp(&right.created_at())
            .then_with(|| left.id().cmp(right.id()))
    });
    values
}

pub(super) fn eq(field: &str, value: &str) -> SqliteFilter {
    SqliteFilter::equal(field, json!(value))
}
