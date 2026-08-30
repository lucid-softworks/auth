#![cfg(feature = "sqlite")]

#[path = "sqlite_adapter_contract/core.rs"]
mod core;
#[path = "sqlite_adapter_contract/migration.rs"]
mod migration;
#[path = "sqlite_adapter_contract/plugin.rs"]
mod plugin;
#[path = "sqlite_adapter_contract/query.rs"]
mod query;
#[path = "sqlite_adapter_contract/storage.rs"]
mod storage;
#[path = "sqlite_adapter_contract/support.rs"]
mod support;
