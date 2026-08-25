use serde::Serialize;
use serde_json::{Map, Number, Value};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CommetCustomerCreate {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommetCustomerUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommetSubscriptionCancel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immediate: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CommetUsageEvent {
    pub feature_code: String,
    pub customer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<CommetUsageProperty>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CommetUsageProperty {
    pub property: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CommetSeatMutation {
    pub customer_id: String,
    pub feature_code: String,
    pub count: Number,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CommetSeatSetAll {
    pub customer_id: String,
    pub seats: Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::CommetCustomerUpdate;
    use serde_json::json;

    #[test]
    fn customer_update_distinguishes_an_omitted_name_from_an_empty_name() {
        assert_eq!(
            serde_json::to_value(CommetCustomerUpdate {
                email: Some("user@example.com".into()),
                full_name: None,
            })
            .unwrap(),
            json!({"email": "user@example.com"})
        );
        assert_eq!(
            serde_json::to_value(CommetCustomerUpdate {
                email: None,
                full_name: Some(String::new()),
            })
            .unwrap(),
            json!({"fullName": ""})
        );
    }
}
