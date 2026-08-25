use serde_json::{Map, Value};

/// Trusted customer identity returned by an Autumn identity callback.
#[derive(Debug, Clone, PartialEq)]
pub struct AutumnIdentity {
    pub customer_id: String,
    pub customer_data: Option<Map<String, Value>>,
}

impl AutumnIdentity {
    pub fn new(customer_id: impl Into<String>) -> Self {
        Self {
            customer_id: customer_id.into(),
            customer_data: None,
        }
    }

    pub fn with_customer_data(mut self, customer_data: Map<String, Value>) -> Self {
        self.customer_data = Some(customer_data);
        self
    }
}
