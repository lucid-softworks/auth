use super::{
    AgentApprovalMethod, AgentApprovalMethodResolver, AgentAuthSchema,
    AgentAutonomousClaimedCallback, AgentAutonomousUserResolver, AgentCapabilitiesResolver,
    AgentCapabilityConstraints, AgentCapabilityQueryResolver, AgentCapabilityValidator,
    AgentDefaultHostCapabilitiesResolver, AgentDynamicHostRegistrationResolver, AgentEventCallback,
    AgentExecuteHandler, AgentFreshSessionWindowResolver, AgentGrantTtlResolver,
    AgentHostClaimedCallback, AgentMode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt, sync::Arc};

pub const DEFAULT_AGENT_JWT_MAX_AGE: u64 = 60;
pub const DEFAULT_AGENT_SESSION_TTL: u64 = 3_600;
pub const DEFAULT_AGENT_MAX_LIFETIME: u64 = 86_400;
pub const DEFAULT_AGENT_MAX_PER_USER: u32 = 25;
pub const DEFAULT_AGENT_FRESH_SESSION_WINDOW: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentJwtFormat {
    Simple,
    Aap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCacheStorage {
    Memory,
    SecondaryStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentApprovalStrength {
    None,
    Session,
    Webauthn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapability {
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_strength: Option<AgentApprovalStrength>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_constraints: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_ttl: Option<u64>,
    #[serde(flatten)]
    pub metadata: Map<String, Value>,
}

impl AgentCapability {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            location: None,
            input: None,
            output: None,
            approval_strength: None,
            required_constraints: None,
            grant_ttl: None,
            metadata: Map::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentCapabilityRequest {
    Name(String),
    Constrained {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        constraints: Option<AgentCapabilityConstraints>,
    },
}

impl AgentCapabilityRequest {
    pub fn name(&self) -> &str {
        match self {
            Self::Name(name) | Self::Constrained { name, .. } => name,
        }
    }

    pub fn constraints(&self) -> Option<&AgentCapabilityConstraints> {
        match self {
            Self::Name(_) => None,
            Self::Constrained { constraints, .. } => constraints.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentProofOfPresenceConfig {
    pub enabled: bool,
    pub rp_id: Option<String>,
    pub origins: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRateLimitRule {
    pub window: u64,
    pub max: u32,
}

#[derive(Clone)]
pub struct AgentAuthConfig {
    pub schema: AgentAuthSchema,
    pub provider_name: Option<String>,
    pub provider_description: Option<String>,
    pub modes: Vec<AgentMode>,
    pub device_authorization_page: String,
    pub approval_methods: Vec<AgentApprovalMethod>,
    pub jwks_uri: Option<String>,
    pub capabilities: Vec<AgentCapability>,
    pub require_auth_for_capabilities: bool,
    pub allowed_key_algorithms: Vec<String>,
    pub jwt_format: AgentJwtFormat,
    pub jwt_max_age: u64,
    pub agent_session_ttl: u64,
    pub max_agents_per_user: u32,
    pub agent_max_lifetime: u64,
    pub absolute_lifetime: u64,
    pub fresh_session_window: u64,
    pub resolve_fresh_session_window: Option<Arc<dyn AgentFreshSessionWindowResolver>>,
    pub allow_dynamic_host_registration: bool,
    pub resolve_dynamic_host_registration: Option<Arc<dyn AgentDynamicHostRegistrationResolver>>,
    pub default_host_capabilities: Vec<String>,
    pub resolve_default_host_capabilities: Option<Arc<dyn AgentDefaultHostCapabilitiesResolver>>,
    pub blocked_capabilities: Vec<String>,
    pub jti_cache_storage: AgentCacheStorage,
    pub jwks_cache_storage: AgentCacheStorage,
    pub dangerously_skip_jti_check: bool,
    pub trust_proxy: bool,
    pub proof_of_presence: AgentProofOfPresenceConfig,
    pub rate_limits: BTreeMap<String, AgentRateLimitRule>,
    pub resolve_approval_method: Option<Arc<dyn AgentApprovalMethodResolver>>,
    pub validate_capabilities: Option<Arc<dyn AgentCapabilityValidator>>,
    pub resolve_autonomous_user: Option<Arc<dyn AgentAutonomousUserResolver>>,
    pub on_host_claimed: Option<Arc<dyn AgentHostClaimedCallback>>,
    pub resolve_grant_ttl: Option<Arc<dyn AgentGrantTtlResolver>>,
    pub on_event: Option<Arc<dyn AgentEventCallback>>,
    pub resolve_capabilities: Option<Arc<dyn AgentCapabilitiesResolver>>,
    pub resolve_query: Option<Arc<dyn AgentCapabilityQueryResolver>>,
    pub on_execute: Option<Arc<dyn AgentExecuteHandler>>,
    pub on_autonomous_agent_claimed: Option<Arc<dyn AgentAutonomousClaimedCallback>>,
}

impl Default for AgentAuthConfig {
    fn default() -> Self {
        Self {
            schema: AgentAuthSchema::default(),
            provider_name: None,
            provider_description: None,
            modes: vec![AgentMode::Delegated, AgentMode::Autonomous],
            device_authorization_page: "/device/capabilities".into(),
            approval_methods: vec![
                AgentApprovalMethod::Ciba,
                AgentApprovalMethod::DeviceAuthorization,
            ],
            jwks_uri: None,
            capabilities: Vec::new(),
            require_auth_for_capabilities: false,
            allowed_key_algorithms: vec!["Ed25519".into()],
            jwt_format: AgentJwtFormat::Simple,
            jwt_max_age: DEFAULT_AGENT_JWT_MAX_AGE,
            agent_session_ttl: DEFAULT_AGENT_SESSION_TTL,
            max_agents_per_user: DEFAULT_AGENT_MAX_PER_USER,
            agent_max_lifetime: DEFAULT_AGENT_MAX_LIFETIME,
            absolute_lifetime: 0,
            fresh_session_window: DEFAULT_AGENT_FRESH_SESSION_WINDOW,
            resolve_fresh_session_window: None,
            allow_dynamic_host_registration: false,
            resolve_dynamic_host_registration: None,
            default_host_capabilities: Vec::new(),
            resolve_default_host_capabilities: None,
            blocked_capabilities: Vec::new(),
            jti_cache_storage: AgentCacheStorage::Memory,
            jwks_cache_storage: AgentCacheStorage::Memory,
            dangerously_skip_jti_check: false,
            trust_proxy: false,
            proof_of_presence: AgentProofOfPresenceConfig::default(),
            rate_limits: BTreeMap::new(),
            resolve_approval_method: None,
            validate_capabilities: None,
            resolve_autonomous_user: None,
            on_host_claimed: None,
            resolve_grant_ttl: None,
            on_event: None,
            resolve_capabilities: None,
            resolve_query: None,
            on_execute: None,
            on_autonomous_agent_claimed: None,
        }
    }
}

impl fmt::Debug for AgentAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentAuthConfig")
            .field("provider_name", &self.provider_name)
            .field("modes", &self.modes)
            .field("capabilities", &self.capabilities)
            .field("allowed_key_algorithms", &self.allowed_key_algorithms)
            .field("jwt_format", &self.jwt_format)
            .field("jwt_max_age", &self.jwt_max_age)
            .field("agent_session_ttl", &self.agent_session_ttl)
            .field("max_agents_per_user", &self.max_agents_per_user)
            .field("agent_max_lifetime", &self.agent_max_lifetime)
            .field("absolute_lifetime", &self.absolute_lifetime)
            .field("fresh_session_window", &self.fresh_session_window)
            .field(
                "allow_dynamic_host_registration",
                &self.allow_dynamic_host_registration,
            )
            .field("blocked_capabilities", &self.blocked_capabilities)
            .field(
                "dangerously_skip_jti_check",
                &self.dangerously_skip_jti_check,
            )
            .field("trust_proxy", &self.trust_proxy)
            .finish_non_exhaustive()
    }
}
