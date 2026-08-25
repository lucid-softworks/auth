use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct DodoCustomer {
    pub customer_id: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoCustomerPage {
    pub items: Vec<DodoCustomer>,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoCustomerPortal {
    pub link: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoProviderProduct {
    pub is_recurring: bool,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoCheckoutSession {
    pub session_id: String,
    pub checkout_url: Option<String>,
    pub client_secret: Option<String>,
    pub payment_id: Option<String>,
    pub publishable_key: Option<String>,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoPaymentOrSubscription {
    pub payment_link: Option<String>,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoProviderItemPage {
    pub items: Vec<Value>,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoUsageIngestResult {
    pub ingested_count: u64,
    pub value: Value,
}
