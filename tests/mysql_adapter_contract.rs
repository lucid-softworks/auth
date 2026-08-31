#![cfg(feature = "mysql")]

#[path = "mysql_adapter_contract/core.rs"]
mod core;
#[path = "mysql_adapter_contract/migration.rs"]
mod migration;
#[path = "mysql_adapter_contract/plugin.rs"]
mod plugin;
#[path = "mysql_adapter_contract/query.rs"]
mod query;
#[path = "mysql_adapter_contract/storage.rs"]
mod storage;
#[path = "mysql_adapter_contract/support.rs"]
mod support;
