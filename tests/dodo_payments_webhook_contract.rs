#![cfg(feature = "axum")]

#[path = "dodo_payments_webhook_contract/delivery.rs"]
mod delivery;
#[path = "dodo_payments_webhook_contract/errors.rs"]
mod errors;
#[path = "dodo_payments_webhook_contract/support.rs"]
mod support;
