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
    AgentAuthConfig, AgentAuthPlugin, AgentAutonomousUserContext, AgentAutonomousUserResolver,
    AgentCapability, AgentExecuteContext, AgentExecuteError, AgentExecuteHandler,
    AgentExecuteResult, AgentSessionUser, ApiKeyConfiguration, ApiKeyPlugin, ApiKeyReference,
    AuthConfig, AuthError, BearerPlugin, DeviceAuthorizationConfig, DeviceAuthorizationPlugin,
    EmailOtpConfig, EmailOtpPlugin, I18nConfig, I18nPlugin, JwtPlugin, LastLoginMethodConfig,
    LastLoginMethodPlugin, MagicLinkConfig, MagicLinkPlugin, McpPlugin, McpPluginConfig,
    MemoryOAuthProviderStore, MemoryStore, MemoryTwoFactorStore, MultiSessionPlugin,
    OAuthDeviceAuthorizationPlugin, OAuthProviderPluginConfig, OAuthProviderStore, OneTapConfig,
    OneTapPlugin, OneTimeTokenConfig, OneTimeTokenPlugin, OpenApiPlugin, OtpConfig, PasskeyConfig,
    PasskeyPlugin, PhoneNumberConfig, PhoneNumberPlugin, PhoneNumberSignUpConfig, SiweConfig,
    SiweMessageVerifier, SiweNonceGenerator, SiwePlugin, SiweVerificationRequest, TotpConfig,
    TwoFactorConfig, TwoFactorPlugin,
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

struct ConformanceAgentExecutor;

struct ConformanceAutonomousUser;

#[async_trait::async_trait]
impl AgentAutonomousUserResolver for ConformanceAutonomousUser {
    async fn resolve(&self, context: AgentAutonomousUserContext) -> Option<AgentSessionUser> {
        Some(AgentSessionUser {
            id: format!("autonomous:{}", context.agent_id),
            name: "Conformance autonomous agent".into(),
            email: "autonomous-agent@example.test".into(),
            attributes: serde_json::Map::new(),
        })
    }
}

#[async_trait::async_trait]
impl AgentExecuteHandler for ConformanceAgentExecutor {
    async fn execute(
        &self,
        context: AgentExecuteContext,
    ) -> Result<AgentExecuteResult, AgentExecuteError> {
        Ok(AgentExecuteResult::Data(serde_json::json!({
            "capability": context.capability,
            "arguments": context.arguments,
            "agent_id": context.agent_session.agent_id,
        })))
    }
}

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
) -> Option<Arc<dyn OAuthProviderStore>> {
    register_agent_auth(config);
    let oauth = register_core_plugins(
        config,
        origin,
        messages,
        phone_number_messages,
        store.clone(),
    );
    super::autumn::register(config);
    super::creem::register(config, store.clone());
    super::dodo_payments::register(config, store.clone());
    super::polar::register(config);
    register_i18n(config);
    config
        .add_plugin(OpenApiPlugin::default())
        .expect("unique Open API plugin");
    oauth
}

fn register_i18n(config: &mut AuthConfig) {
    let translations = BTreeMap::from([(
        "fr".into(),
        BTreeMap::from([(
            "INVALID_EMAIL_OR_PASSWORD".into(),
            "Email ou mot de passe invalide".into(),
        )]),
    )]);
    let mut i18n = I18nConfig::new(translations).expect("non-empty i18n translations");
    i18n.default_locale = "unavailable".into();
    config
        .add_plugin(I18nPlugin::new(i18n).expect("valid i18n configuration"))
        .expect("unique i18n plugin");
}

fn register_agent_auth(config: &mut AuthConfig) {
    let mut agent_auth = AgentAuthConfig::default();
    agent_auth.provider_name = Some("Lucid Agent Conformance".into());
    agent_auth.allow_dynamic_host_registration = true;
    agent_auth.capabilities = vec![
        AgentCapability::new("notes.read", "Read notes"),
        AgentCapability::new("notes.write", "Write notes"),
    ];
    agent_auth.default_host_capabilities = vec!["notes.read".into()];
    agent_auth.on_execute = Some(Arc::new(ConformanceAgentExecutor));
    agent_auth.resolve_autonomous_user = Some(Arc::new(ConformanceAutonomousUser));
    config
        .add_plugin(AgentAuthPlugin::in_memory(agent_auth).expect("valid Agent Auth schema"))
        .expect("unique Agent Auth plugin");
}

fn register_core_plugins(
    config: &mut AuthConfig,
    origin: &str,
    messages: &ConformanceMessages,
    phone_number_messages: &ConformancePhoneNumberMessages,
    store: Arc<MemoryStore>,
) -> Option<Arc<dyn OAuthProviderStore>> {
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
    let oauth = register_session_plugins(config, origin, store.clone());
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
    oauth
}

fn register_session_plugins(
    config: &mut AuthConfig,
    origin: &str,
    store: Arc<MemoryStore>,
) -> Option<Arc<dyn OAuthProviderStore>> {
    config
        .add_plugin(JwtPlugin::default())
        .expect("unique JWT plugin");
    let oauth = register_device_authorization(config, origin);
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
    oauth
}

fn register_device_authorization(
    config: &mut AuthConfig,
    origin: &str,
) -> Option<Arc<dyn OAuthProviderStore>> {
    let mut device = DeviceAuthorizationConfig::default();
    device.interval = "0s".into();
    match std::env::var("LUCID_AUTH_DEVICE_MODE").as_deref() {
        Ok("standalone") => {
            config
                .add_plugin(DeviceAuthorizationPlugin::in_memory(device))
                .expect("unique standalone device-authorization plugin");
            None
        }
        Ok("oauth") | Err(_) => {
            let oauth = Arc::new(MemoryOAuthProviderStore::new());
            let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
            provider.scopes.push("mcp.read".into());
            let mcp = McpPlugin::from_arc(
                McpPluginConfig::new(format!("{origin}/mcp"), provider),
                oauth as Arc<_>,
            )
            .expect("valid MCP OAuth preset");
            let runtime_store = mcp.store().clone();
            config
                .add_plugin(mcp)
                .expect("unique MCP OAuth-provider plugin");
            config
                .add_plugin(OAuthDeviceAuthorizationPlugin::in_memory(device))
                .expect("unique OAuth device-authorization plugin");
            Some(runtime_store)
        }
        Ok(mode) => panic!("unsupported LUCID_AUTH_DEVICE_MODE `{mode}`"),
    }
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
