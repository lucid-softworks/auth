#![cfg(feature = "axum")]

#[path = "jwt_contract/adapter_rotation.rs"]
mod adapter_rotation;
#[path = "jwt_contract/algorithms.rs"]
mod algorithms;
#[path = "jwt_contract/claims.rs"]
mod claims;
#[path = "jwt_contract/cookie_cache.rs"]
mod cookie_cache;
#[path = "jwt_contract/header.rs"]
mod header;
#[path = "jwt_contract/metadata.rs"]
mod metadata;
#[path = "jwt_contract/secrets.rs"]
mod secrets;
#[path = "jwt_contract/support.rs"]
mod support;
#[path = "jwt_contract/verification.rs"]
mod verification;
