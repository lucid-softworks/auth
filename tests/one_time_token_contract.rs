#![cfg(feature = "axum")]

#[path = "one_time_token_contract/endpoints.rs"]
mod endpoints;
#[path = "one_time_token_contract/header.rs"]
mod header;
#[path = "one_time_token_contract/metadata.rs"]
mod metadata;
#[path = "one_time_token_contract/storage.rs"]
mod storage;
#[path = "one_time_token_contract/support.rs"]
mod support;
