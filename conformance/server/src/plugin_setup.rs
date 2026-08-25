use super::{
    email::{
        ConformanceEmailOtpSender, ConformanceMagicLinkSender, ConformanceMessages,
        ConformanceOtpSender,
    },
    native_plugin::ConformancePlugin,
    organization,
    phone_number::{
        ConformancePhoneNumberMessages, ConformancePhoneNumberSender,
        ConformancePhoneNumberTemporaryEmail, ConformancePhoneNumberTemporaryName,
    },
};
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyPlugin, ApiKeyReference, AuthConfig, AuthError, BearerPlugin,
    EmailOtpConfig, EmailOtpPlugin, JwtPlugin, LastLoginMethodConfig, LastLoginMethodPlugin,
    MagicLinkConfig, MagicLinkPlugin, MemoryStore, MemoryTwoFactorStore, MultiSessionPlugin,
    OAuthProviderPlugin, OAuthProviderPluginConfig, OneTapConfig, OneTapPlugin,
    OneTimeTokenConfig, OneTimeTokenPlugin, OtpConfig, PasskeyConfig, PasskeyPlugin,
    PhoneNumberConfig, PhoneNumberPlugin, PhoneNumberSignUpConfig, SiweConfig, SiweMessageVerifier,
    SiweNonceGenerator, SiwePlugin, SiweVerificationRequest, TotpConfig, TwoFactorConfig,
    TwoFactorPlugin,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

struct ConformanceSiweNonce(AtomicU64);

#[async_trait::async_trait]
impl SiweNonceGenerator for ConformanceSiweNonce {
    async fn generate(&self) -> Result<String, AuthError> {
        Ok(format!(
            "nonce{:08}",
            self.0.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

struct ConformanceSiweVerifier;

#[async_trait::async_trait]
impl SiweMessageVerifier for ConformanceSiweVerifier {
    async fn verify(&self, _: SiweVerificationRequest) -> Result<bool, AuthError> {
        Ok(true)
    }
}

pub(super) fn register(
    config: &mut AuthConfig,
    origin: &str,
    messages: &ConformanceMessages,
    phone_number_messages: &ConformancePhoneNumberMessages,
    store: Arc<MemoryStore>,
) {
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
    let mut email_otp = EmailOtpConfig::new(Arc::new(ConformanceEmailOtpSender {
        messages: messages.email_otps.clone(),
    }));
    email_otp.change_email.enabled = true;
    config
        .add_plugin(EmailOtpPlugin::new(email_otp))
        .expect("unique email-OTP plugin");
    register_phone_number(config, phone_number_messages, store.clone());
    register_session_plugins(config, origin, store.clone());
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

fn register_session_plugins(config: &mut AuthConfig, origin: &str, store: Arc<MemoryStore>) {
    config
        .add_plugin(JwtPlugin::default())
        .expect("unique JWT plugin");
    config
        .add_plugin(OAuthProviderPlugin::in_memory(OAuthProviderPluginConfig::new(
            "/login", "/consent",
        )))
        .expect("unique OAuth-provider plugin");
    config
        .add_plugin(BearerPlugin::default())
        .expect("unique bearer plugin");
    config
        .add_plugin(OneTimeTokenPlugin::new(OneTimeTokenConfig {
            set_ott_header_on_new_session: true,
            ..OneTimeTokenConfig::default()
        }))
        .expect("unique one-time-token plugin");
    let one_tap = OneTapConfig::default().with_client_id("conformance-google-client");
    config
        .add_plugin(OneTapPlugin::new(one_tap))
        .expect("unique one-tap plugin");
    config
        .add_plugin(MultiSessionPlugin::default())
        .expect("unique multi-session plugin");
    config
        .add_plugin(LastLoginMethodPlugin::new(LastLoginMethodConfig {
            store_in_database: true,
            ..LastLoginMethodConfig::default()
        }))
        .expect("unique last-login-method plugin");
    let siwe = SiweConfig::new(
        origin.trim_start_matches("http://"),
        Arc::new(ConformanceSiweNonce(AtomicU64::new(1))),
        Arc::new(ConformanceSiweVerifier),
    );
    config
        .add_plugin(SiwePlugin::new(store, siwe))
        .expect("unique SIWE plugin");
}

fn register_phone_number(
    config: &mut AuthConfig,
    messages: &ConformancePhoneNumberMessages,
    store: Arc<MemoryStore>,
) {
    config
        .add_plugin(PhoneNumberPlugin::new(
            store,
            PhoneNumberConfig {
                send_otp: Some(Arc::new(ConformancePhoneNumberSender {
                    messages: messages.verification.clone(),
                })),
                send_password_reset_otp: Some(Arc::new(ConformancePhoneNumberSender {
                    messages: messages.password_reset.clone(),
                })),
                sign_up_on_verification: Some(PhoneNumberSignUpConfig {
                    temporary_email: Arc::new(ConformancePhoneNumberTemporaryEmail),
                    temporary_name: Some(Arc::new(ConformancePhoneNumberTemporaryName)),
                }),
                ..PhoneNumberConfig::default()
            },
        ))
        .expect("unique phone-number plugin");
}
