use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DashPeriod {
    #[default]
    Daily,
    Weekly,
    Monthly,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DashAdapterOperator {
    #[default]
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    Contains,
    #[serde(rename = "starts_with")]
    StartsWith,
    #[serde(rename = "ends_with")]
    EndsWith,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DashAdapterConnector {
    #[serde(rename = "AND")]
    And,
    #[serde(rename = "OR")]
    Or,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DashSortDirection {
    #[default]
    Asc,
    Desc,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashAdapterWhere {
    pub field: String,
    pub value: Value,
    #[serde(default)]
    pub operator: DashAdapterOperator,
    pub connector: Option<DashAdapterConnector>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashAdapterSort {
    pub field: String,
    pub direction: DashSortDirection,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum DashAdapterAction {
    FindOne {
        model: String,
        #[serde(rename = "where")]
        where_clause: Option<Vec<DashAdapterWhere>>,
        select: Option<Vec<String>>,
        join: Option<std::collections::BTreeMap<String, bool>>,
    },
    FindMany {
        model: String,
        #[serde(rename = "where")]
        where_clause: Option<Vec<DashAdapterWhere>>,
        limit: Option<f64>,
        offset: Option<f64>,
        sort_by: Option<DashAdapterSort>,
        join: Option<std::collections::BTreeMap<String, bool>>,
    },
    Create {
        model: String,
        data: Map<String, Value>,
    },
    Update {
        model: String,
        #[serde(rename = "where")]
        where_clause: Vec<DashAdapterWhere>,
        update: Map<String, Value>,
    },
    Count {
        model: String,
        #[serde(rename = "where")]
        where_clause: Option<Vec<DashAdapterWhere>>,
    },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DashUserListQuery {
    pub limit: Option<f64>,
    pub offset: Option<f64>,
    pub sort_by: Option<String>,
    pub sort_order: Option<DashSortDirection>,
    pub where_clause: Option<Vec<Value>>,
    pub count_where: Option<Vec<Value>>,
}

impl DashUserListQuery {
    pub fn adapter_limit(&self) -> usize {
        clamp(self.limit, 10.0, 1.0, 100.0) as usize
    }

    pub fn adapter_offset(&self) -> usize {
        clamp(self.offset, 0.0, 0.0, f64::MAX) as usize
    }

    pub fn response_limit(&self) -> f64 {
        self.limit.unwrap_or(10.0)
    }

    pub fn response_offset(&self) -> f64 {
        self.offset.unwrap_or(0.0)
    }
}

fn clamp(value: Option<f64>, fallback: f64, minimum: f64, maximum: f64) -> f64 {
    let value = value.filter(|value| value.is_finite()).unwrap_or(fallback);
    value.floor().clamp(minimum, maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_limits_match_the_runtime_clamps_but_preserve_response_values() {
        let query = DashUserListQuery {
            limit: Some(150.5),
            offset: Some(-2.1),
            ..DashUserListQuery::default()
        };
        assert_eq!(query.adapter_limit(), 100);
        assert_eq!(query.adapter_offset(), 0);
        assert_eq!(query.response_limit(), 150.5);
        assert_eq!(query.response_offset(), -2.1);
    }

    #[test]
    fn adapter_union_rejects_unpublished_actions_and_operators() {
        assert!(
            serde_json::from_value::<DashAdapterAction>(serde_json::json!({
                "action": "delete",
                "model": "user"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DashAdapterAction>(serde_json::json!({
                "action": "findMany",
                "model": "user",
                "where": [{"field": "id", "value": "u1", "operator": "not_in"}]
            }))
            .is_err()
        );
    }
}
