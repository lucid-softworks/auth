use super::codec;
use crate::{
    AgentApprovalRequest, AgentCapabilityGrant, AgentHost, AgentIdentity, AuthError,
    mongodb::{MongoFilter, MongoFindOptions, MongoSort, MongoSortDirection, MongoStore},
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

pub(super) async fn find<T>(
    store: &MongoStore,
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
    store: &MongoStore,
    model: &str,
    field: &str,
    value: &str,
    decode: fn(Map<String, Value>) -> Result<T, AuthError>,
) -> Result<Vec<T>, AuthError> {
    let values = store
        .find_records(model, &[eq(field, value)], &MongoFindOptions::default())
        .await?
        .into_iter()
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(order(values))
}

pub(super) async fn list_pending(
    store: &MongoStore,
    field: &str,
    value: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    let values = store
        .find_records(
            "approvalRequest",
            &[eq(field, value), eq("status", "pending")],
            &MongoFindOptions::default(),
        )
        .await?
        .into_iter()
        .map(codec::decode_approval)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(order(values))
}

pub(super) fn first_by_id() -> MongoFindOptions {
    MongoFindOptions {
        sort: Some(MongoSort {
            field: "id".into(),
            direction: MongoSortDirection::Ascending,
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

pub(super) fn eq(field: &str, value: &str) -> MongoFilter {
    MongoFilter::equal(field, json!(value))
}
