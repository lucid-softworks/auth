mod callbacks;
mod config;
mod memory;
mod metadata;
mod model;
mod plugin;
mod server;
#[cfg(any(feature = "axum", test))]
mod service;
mod store;

#[cfg(feature = "axum")]
mod axum;
#[cfg(feature = "postgres")]
mod postgres;
mod provider;
mod schema;
mod transport;
mod webhook;

pub use callbacks::{
    CreemCallbackError, CreemWebhookCallback, CreemWebhookCallbacks, FnCreemWebhookCallback,
    SyncCreemWebhookCallback,
};
pub use config::CreemOptions;
pub use memory::MemoryCreemStore;
pub use model::CreemSubscription;
pub use plugin::CreemPlugin;
#[cfg(feature = "postgres")]
pub use postgres::PostgresCreemStore;
pub use provider::{
    CreemCheckboxFieldConfig, CreemCheckout, CreemCheckoutCustomer, CreemCheckoutRequest,
    CreemCustomField, CreemCustomFieldType, CreemMetadata, CreemPortal, CreemPortalRequest,
    CreemProviderSubscription, CreemTextFieldConfig, CreemTransactionPage, CreemTransactionSearch,
};
pub use schema::schema_tables as creem_schema_tables;
pub use schema::{CreemModelSchema, CreemSchema, CreemSchemaError};
pub use server::{
    CreemActiveSubscription, CreemCancellation, CreemRedirect, CreemServerAccess,
    CreemServerCheckoutInput, CreemServerConfig, cancel_creem_subscription,
    check_creem_subscription_access, create_creem_checkout, create_creem_client,
    create_creem_portal, format_creem_date, get_active_creem_subscriptions,
    get_creem_days_until_renewal, is_active_creem_subscription, retrieve_creem_subscription,
    search_creem_transactions, validate_creem_server_webhook_signature,
};
pub use store::{CreemStore, CreemStoreError, CreemStoredUser, CreemSubscriptionPatch};
pub use transport::{CreemHttpTransport, CreemProviderConfig, CreemProviderError, CreemTransport};
pub use webhook::{
    CreemPersistenceError, CreemWebhookError, CreemWebhookEvent, CreemWebhookPersistence,
    NoopCreemWebhookPersistence, decode_webhook_text as decode_creem_webhook_text,
    parse_webhook_event as parse_creem_webhook_event, process_webhook as process_creem_webhook,
    sign_webhook_text as sign_creem_webhook_text,
    validate_webhook_signature as validate_creem_webhook_signature,
};

pub const CREEM_ADAPTER_VERSION: &str = "1.1.4";
pub const CREEM_SDK_VERSION: &str = "1.6.0";
