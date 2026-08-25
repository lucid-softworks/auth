use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct CreemCheckout {
    pub checkout_url: Option<String>,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreemPortal {
    pub customer_portal_link: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreemProviderSubscription {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreemTransactionPage {
    pub value: Value,
    pub next_page: Option<f64>,
}
