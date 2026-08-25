#![cfg(feature = "axum")]

#[path = "oauth_proxy_contract/flow.rs"]
mod flow;
#[path = "oauth_proxy_contract/metadata.rs"]
mod metadata;
#[path = "oauth_proxy_contract/security.rs"]
mod security;
#[path = "oauth_proxy_contract/support.rs"]
mod support;
#[path = "oauth_proxy_contract/transport.rs"]
mod transport;
