use super::{
    cookie_cache,
    email::{self, ConformanceMessages},
    phone_number::ConformancePhoneNumberMessages,
    plugin_setup, rate_limit, social_provider,
};
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AdminConfig, AdminPlugin, AdminRole, AuthConfig,
    MemorySecondaryStorage, MemoryStore, OAuthProviderStore, UsernamePlugin,
};
use serde_json::json;
use std::sync::Arc;

pub(super) async fn build(
    origin: &str,
    messages: &ConformanceMessages,
    phone_number_messages: &ConformancePhoneNumberMessages,
    store: Arc<MemoryStore>,
    secondary: Arc<MemorySecondaryStorage>,
) -> (AuthConfig, Option<Arc<dyn OAuthProviderStore>>) {
    let mut config = AuthConfig::new([82_u8; 32]).expect("fixture secret");
    config.secondary_storage = Some(secondary);
    config.session.store_session_in_database = true;
    config.account.store_account_cookie = true;
    cookie_cache::configure(&mut config);
    configure_deferred_refresh(&mut config);
    configure_admin(&mut config);
    config
        .add_plugin(lucid_auth::AnonymousPlugin::default())
        .expect("unique anonymous plugin");
    config.email_and_password.enabled = true;
    config.user.delete_user.enabled = true;
    config.user.change_email.enabled = true;
    configure_additional_fields(&mut config);
    email::configure(&mut config, messages);
    config
        .set_base_url(origin)
        .expect("localhost fixture origin");
    rate_limit::configure(&mut config);
    social_provider::register(&mut config).await;
    config
        .add_plugin(UsernamePlugin::default())
        .expect("unique username plugin");
    let oauth = plugin_setup::register(&mut config, origin, messages, phone_number_messages, store);
    (config, oauth)
}

fn configure_deferred_refresh(config: &mut AuthConfig) {
    if std::env::var_os("LUCID_AUTH_DEFER_SESSION_REFRESH").is_some() {
        config.session.cookie_cache.enabled = false;
        config.session.defer_session_refresh = true;
        config.session.update_age = chrono::Duration::zero();
    }
}

fn configure_admin(config: &mut AuthConfig) {
    let mut admin = AdminConfig::default();
    admin.set_role("member", AdminRole::new());
    admin.set_role("viewer", AdminRole::new());
    config
        .add_plugin(AdminPlugin::new(admin))
        .expect("unique admin plugin");
}

fn configure_additional_fields(config: &mut AuthConfig) {
    config.user.additional_fields.insert(
        "timezone".into(),
        AdditionalField::new(AdditionalFieldType::String).default_value(json!("UTC")),
    );
    config.user.additional_fields.insert(
        "department".into(),
        AdditionalField::new(AdditionalFieldType::String).optional(),
    );
    config.session.additional_fields.insert(
        "theme".into(),
        AdditionalField::new(AdditionalFieldType::String).default_value(json!("system")),
    );
}
