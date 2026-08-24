use super::{
    email::{ConformanceMagicLinkSender, ConformanceMessages, ConformanceOtpSender},
    native_plugin::ConformancePlugin,
    organization,
};
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyPlugin, ApiKeyReference, AuthConfig, MagicLinkConfig,
    MagicLinkPlugin, MemoryTwoFactorStore, OtpConfig, PasskeyConfig, PasskeyPlugin, TotpConfig,
    TwoFactorConfig, TwoFactorPlugin,
};
use std::{collections::BTreeMap, sync::Arc};

pub(super) fn register(config: &mut AuthConfig, origin: &str, messages: &ConformanceMessages) {
    config
        .add_plugin(PasskeyPlugin::new(PasskeyConfig {
            rp_id: Some("localhost".into()),
            rp_name: Some("lucid-auth conformance".into()),
            origins: Some(vec![origin.into()]),
            ..PasskeyConfig::default()
        }))
        .expect("unique passkey plugin");
    organization::register(config);
    config
        .add_plugin(ApiKeyPlugin::with_configurations(vec![
            ApiKeyConfiguration {
                enable_metadata: true,
                enable_session_for_api_keys: true,
                default_permissions: Some(BTreeMap::from([(
                    "documents".into(),
                    vec!["read".into()],
                )])),
                ..ApiKeyConfiguration::default()
            },
            ApiKeyConfiguration {
                config_id: "organization".into(),
                reference: ApiKeyReference::Organization,
                ..ApiKeyConfiguration::default()
            },
        ]))
        .expect("unique API-key plugin");
    config
        .add_plugin(ConformancePlugin)
        .expect("unique conformance plugin");
    config
        .add_plugin(MagicLinkPlugin::new(MagicLinkConfig::new(Arc::new(
            ConformanceMagicLinkSender {
                messages: messages.magic_links.clone(),
            },
        ))))
        .expect("unique magic-link plugin");
    config
        .add_plugin(TwoFactorPlugin::new(
            Arc::new(MemoryTwoFactorStore::default()),
            TwoFactorConfig {
                totp: TotpConfig {
                    period: chrono::Duration::seconds(1),
                    ..TotpConfig::default()
                },
                otp: Some(OtpConfig::new(Arc::new(ConformanceOtpSender {
                    messages: messages.two_factor_otps.clone(),
                }))),
                ..TwoFactorConfig::default()
            },
        ))
        .expect("unique two-factor plugin");
}
