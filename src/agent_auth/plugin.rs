use super::{
    AgentAuthConfig, AgentAuthStore, MemoryAgentAuthStore, endpoints::AGENT_AUTH_ENDPOINTS, schema,
};
use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginRateLimit,
};
use std::{borrow::Cow, fmt, sync::Arc};

#[derive(Clone)]
pub struct AgentAuthPlugin {
    config: Arc<AgentAuthConfig>,
    store: Arc<dyn AgentAuthStore>,
}

impl AgentAuthPlugin {
    pub fn new<S>(config: AgentAuthConfig, store: S) -> Result<Self, AuthError>
    where
        S: AgentAuthStore + 'static,
    {
        Self::from_arc(config, Arc::new(store))
    }

    pub fn from_arc(
        mut config: AgentAuthConfig,
        store: Arc<dyn AgentAuthStore>,
    ) -> Result<Self, AuthError> {
        validate_capability_locations(&config)?;
        if config.proof_of_presence.rp_id.as_deref() == Some("") {
            config.proof_of_presence.rp_id = None;
        }
        Ok(Self {
            config: Arc::new(config),
            store,
        })
    }

    pub fn in_memory(config: AgentAuthConfig) -> Result<Self, AuthError> {
        Self::new(config, MemoryAgentAuthStore::default())
    }

    pub fn config(&self) -> &AgentAuthConfig {
        &self.config
    }

    pub fn store(&self) -> &Arc<dyn AgentAuthStore> {
        &self.store
    }
}

impl fmt::Debug for AgentAuthPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentAuthPlugin")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for AgentAuthPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "agent-auth",
            display_name: "Better Auth Agent Auth",
            version: "0.6.2",
            provenance: crate::PluginProvenance::pinned_upstream(
                "@better-auth/agent-auth",
                "0.6.2",
                "@better-auth/agent-auth",
                "agentAuth",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(AGENT_AUTH_ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "@better-auth/agent-auth",
                "@better-auth/agent-auth/client",
                "agentAuthClient",
            )),
        }
    }

    fn validate(&self, config: &AuthConfig) -> Result<(), AuthError> {
        if self.config.proof_of_presence.enabled && !has_passkey_plugin(config) {
            eprintln!(
                "[agent-auth] proofOfPresence is enabled but the passkey plugin is not installed. WebAuthn-gated approvals require @better-auth/passkey to be added to your plugins array so users can register authenticators."
            );
        }
        Ok(())
    }

    fn schema(&self) -> Vec<crate::PluginSchemaTable> {
        schema::schema_tables(&self.config.schema)
    }

    fn rate_limits(&self) -> Vec<PluginRateLimit> {
        agent_auth_rate_limits(&self.config)
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(self.config.clone(), self.store.clone(), service)
    }

    #[cfg(feature = "axum")]
    fn root_routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::root_routes(self.config.clone(), self.store.clone(), service)
    }
}

fn validate_capability_locations(config: &AgentAuthConfig) -> Result<(), AuthError> {
    for capability in &config.capabilities {
        let Some(location) = capability.location.as_deref() else {
            continue;
        };
        if url::Url::parse(location).is_err() {
            return Err(AuthError::InvalidConfiguration(format!(
                "[agent-auth] Capability \"{}\" has an invalid location URL: \"{location}\". The location must be an absolute URL (e.g. \"https://api.example.com/execute\").",
                capability.name
            )));
        }
    }
    Ok(())
}

fn has_passkey_plugin(config: &AuthConfig) -> bool {
    config
        .plugins
        .iter()
        .any(|plugin| plugin.descriptor().id == "passkey")
}

const ORDINARY_RATE_PATHS: &[&str] = &[
    "/capability/list",
    "/capability/describe",
    "/capability/execute",
    "/capability/batch-execute",
    "/agent/list",
    "/agent/get",
    "/agent/update",
    "/agent/revoke",
    "/agent/revoke-capability",
    "/agent/reactivate",
    "/agent/session",
    "/agent/request-capability",
    "/agent/introspect",
    "/agent/grant-capability",
    "/agent/claim",
    "/agent/device/code",
];

fn agent_auth_rate_limits(config: &AgentAuthConfig) -> Vec<PluginRateLimit> {
    let mut limits = Vec::new();
    push_limit(&mut limits, config, "/agent/register", 60, 10);
    let rotation = override_rule(config, "/agent/rotate-key")
        .or_else(|| override_rule(config, "/agent/cleanup"));
    for path in ["/agent/rotate-key", "/agent/cleanup"] {
        push_resolved(&mut limits, path, rotation, 60, 5);
    }
    push_limit(&mut limits, config, "/agent/approve-capability", 60, 5);
    push_limit(&mut limits, config, "/agent/ciba/authorize", 60, 5);
    let polling = override_rule(config, "/agent/status")
        .or_else(|| override_rule(config, "/agent/ciba/pending"));
    for path in ["/agent/status", "/agent/ciba/pending"] {
        push_resolved(&mut limits, path, polling, 60, 300);
    }
    for path in ORDINARY_RATE_PATHS {
        push_resolved(&mut limits, path, None, 60, 60);
    }
    limits
}

fn push_limit(
    limits: &mut Vec<PluginRateLimit>,
    config: &AgentAuthConfig,
    path: &'static str,
    window: u64,
    max: u32,
) {
    push_resolved(limits, path, override_rule(config, path), window, max);
}

fn push_resolved(
    limits: &mut Vec<PluginRateLimit>,
    path: &'static str,
    configured: Option<super::AgentRateLimitRule>,
    window: u64,
    max: u32,
) {
    let configured = configured.unwrap_or(super::AgentRateLimitRule { window, max });
    limits.push(PluginRateLimit {
        path,
        window: configured.window,
        max: configured.max,
    });
}

fn override_rule(config: &AgentAuthConfig, path: &str) -> Option<super::AgentRateLimitRule> {
    config.rate_limits.get(path).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentCapability, PasskeyConfig, PasskeyPlugin};

    #[test]
    fn descriptor_and_rate_groups_match_agent_auth_0_6_2() {
        let plugin = AgentAuthPlugin::in_memory(AgentAuthConfig::default()).unwrap();
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "agent-auth");
        assert_eq!(descriptor.endpoints.len(), 32);
        assert_eq!(plugin.rate_limits().len(), 23);
        assert_eq!(
            plugin
                .rate_limits()
                .iter()
                .find(|rule| rule.path == "/agent/status")
                .unwrap()
                .max,
            300
        );
        assert!(
            !plugin
                .rate_limits()
                .iter()
                .any(|rule| rule.path.starts_with("/host/"))
        );
    }

    #[test]
    fn rejects_relative_capability_locations_with_the_upstream_message() {
        let mut config = AgentAuthConfig::default();
        let mut capability = AgentCapability::new("mail.send", "Send mail");
        capability.location = Some("/execute".into());
        config.capabilities.push(capability);
        let error = AgentAuthPlugin::in_memory(config).unwrap_err();
        assert_eq!(
            error.to_string(),
            "authentication configuration is invalid: [agent-auth] Capability \"mail.send\" has an invalid location URL: \"/execute\". The location must be an absolute URL (e.g. \"https://api.example.com/execute\")."
        );
    }

    #[test]
    fn accepts_absolute_locations_and_normalizes_an_empty_presence_rp_id() {
        let mut config = AgentAuthConfig::default();
        let mut capability = AgentCapability::new("mail.send", "Send mail");
        capability.location = Some("https://api.example.com/execute".into());
        config.capabilities.push(capability);
        config.proof_of_presence.enabled = true;
        config.proof_of_presence.rp_id = Some(String::new());
        let plugin = AgentAuthPlugin::in_memory(config).unwrap();
        assert_eq!(plugin.config().proof_of_presence.rp_id, None);
    }

    #[test]
    fn detects_the_passkey_plugin_for_presence_initialization() {
        let mut auth = AuthConfig::new(vec![b's'; 32]).unwrap();
        assert!(!has_passkey_plugin(&auth));
        auth.add_plugin(PasskeyPlugin::new(PasskeyConfig::default()))
            .unwrap();
        assert!(has_passkey_plugin(&auth));
    }
}
