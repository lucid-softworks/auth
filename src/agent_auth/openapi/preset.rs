use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use serde_json::Value;

use super::{
    handler::{AgentOpenApiHandlerOptions, OpenApiExecuteHandler},
    parse::{ParsedCapability, parse_capabilities},
};
use crate::{
    AgentApprovalStrength, AgentAuthConfig, AgentCapability, AgentDefaultHostCapabilitiesContext,
    AgentDefaultHostCapabilitiesResolver, AgentExecuteHandler,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOpenApiCapabilityInfo {
    pub name: String,
    pub method: String,
    pub description: String,
}

#[async_trait]
pub trait AgentOpenApiDefaultCapabilityFilter: Send + Sync {
    async fn include(
        &self,
        capability: AgentOpenApiCapabilityInfo,
        context: &AgentDefaultHostCapabilitiesContext,
    ) -> bool;
}

pub trait AgentOpenApiApprovalStrengthResolver: Send + Sync {
    fn resolve(&self, capability: AgentOpenApiCapabilityInfo) -> AgentApprovalStrength;
}

#[derive(Clone)]
pub enum AgentOpenApiDefaultCapabilities {
    All,
    Methods(Vec<String>),
    Dynamic(Arc<dyn AgentOpenApiDefaultCapabilityFilter>),
}

impl fmt::Debug for AgentOpenApiDefaultCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => formatter.write_str("All"),
            Self::Methods(methods) => formatter.debug_tuple("Methods").field(methods).finish(),
            Self::Dynamic(_) => formatter.write_str("Dynamic(..)"),
        }
    }
}

#[derive(Clone)]
pub enum AgentOpenApiApprovalStrength {
    All(AgentApprovalStrength),
    Methods(BTreeMap<String, AgentApprovalStrength>),
    Dynamic(Arc<dyn AgentOpenApiApprovalStrengthResolver>),
}

impl fmt::Debug for AgentOpenApiApprovalStrength {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All(strength) => formatter.debug_tuple("All").field(strength).finish(),
            Self::Methods(methods) => formatter.debug_tuple("Methods").field(methods).finish(),
            Self::Dynamic(_) => formatter.write_str("Dynamic(..)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateAgentFromOpenApiOptions {
    pub handler: AgentOpenApiHandlerOptions,
    pub default_host_capabilities: Option<AgentOpenApiDefaultCapabilities>,
    pub approval_strength: Option<AgentOpenApiApprovalStrength>,
    pub location: Option<String>,
}

impl CreateAgentFromOpenApiOptions {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            handler: AgentOpenApiHandlerOptions::new(base_url),
            default_host_capabilities: None,
            approval_strength: None,
            location: None,
        }
    }
}

#[derive(Clone)]
pub struct AgentOpenApiPreset {
    pub provider_name: Option<String>,
    pub provider_description: Option<String>,
    pub capabilities: Vec<AgentCapability>,
    pub on_execute: Arc<dyn AgentExecuteHandler>,
    pub default_host_capabilities: Option<Vec<String>>,
    pub resolve_default_host_capabilities: Option<Arc<dyn AgentDefaultHostCapabilitiesResolver>>,
}

impl AgentOpenApiPreset {
    pub fn apply_to(self, config: &mut AgentAuthConfig) {
        if let Some(provider_name) = self.provider_name {
            config.provider_name = Some(provider_name);
        }
        if let Some(provider_description) = self.provider_description {
            config.provider_description = Some(provider_description);
        }
        config.capabilities = self.capabilities;
        config.on_execute = Some(self.on_execute);
        if let Some(defaults) = self.default_host_capabilities {
            config.default_host_capabilities = defaults;
        }
        if let Some(resolver) = self.resolve_default_host_capabilities {
            config.resolve_default_host_capabilities = Some(resolver);
        }
    }
}

impl fmt::Debug for AgentOpenApiPreset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentOpenApiPreset")
            .field("provider_name", &self.provider_name)
            .field("provider_description", &self.provider_description)
            .field("capabilities", &self.capabilities)
            .field("default_host_capabilities", &self.default_host_capabilities)
            .field(
                "resolve_default_host_capabilities",
                &self.resolve_default_host_capabilities.is_some(),
            )
            .finish_non_exhaustive()
    }
}

pub(super) fn create_preset(
    spec: &Value,
    options: CreateAgentFromOpenApiOptions,
) -> AgentOpenApiPreset {
    let parsed = parse_capabilities(spec);
    let capabilities = parsed
        .iter()
        .cloned()
        .map(|mut parsed| {
            if let Some(filter) = &options.approval_strength {
                parsed.capability.approval_strength = resolve_strength(&parsed, filter);
            }
            if let Some(location) = options.location.as_ref().filter(|value| !value.is_empty()) {
                parsed.capability.location = Some(location.clone());
            }
            parsed.capability
        })
        .collect();
    let (defaults, resolver) = resolve_defaults(&parsed, options.default_host_capabilities);
    let provider_name = info_string(spec, "title");
    let provider_description = info_string(spec, "description");
    AgentOpenApiPreset {
        provider_name,
        provider_description,
        capabilities,
        on_execute: Arc::new(OpenApiExecuteHandler::new(spec, options.handler)),
        default_host_capabilities: defaults,
        resolve_default_host_capabilities: resolver,
    }
}

fn resolve_strength(
    parsed: &ParsedCapability,
    filter: &AgentOpenApiApprovalStrength,
) -> Option<AgentApprovalStrength> {
    match filter {
        AgentOpenApiApprovalStrength::All(strength) => Some(*strength),
        AgentOpenApiApprovalStrength::Methods(methods) => methods.get(&parsed.method).copied(),
        AgentOpenApiApprovalStrength::Dynamic(resolve) => Some(resolve.resolve(info(parsed))),
    }
}

fn resolve_defaults(
    parsed: &[ParsedCapability],
    filter: Option<AgentOpenApiDefaultCapabilities>,
) -> (
    Option<Vec<String>>,
    Option<Arc<dyn AgentDefaultHostCapabilitiesResolver>>,
) {
    match filter {
        None => (None, None),
        Some(AgentOpenApiDefaultCapabilities::All) => (
            Some(
                parsed
                    .iter()
                    .map(|parsed| parsed.capability.name.clone())
                    .collect(),
            ),
            None,
        ),
        Some(AgentOpenApiDefaultCapabilities::Methods(methods)) => {
            let methods = methods
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect::<std::collections::BTreeSet<_>>();
            (
                Some(
                    parsed
                        .iter()
                        .filter(|parsed| methods.contains(&parsed.method))
                        .map(|parsed| parsed.capability.name.clone())
                        .collect(),
                ),
                None,
            )
        }
        Some(AgentOpenApiDefaultCapabilities::Dynamic(filter)) => (
            None,
            Some(Arc::new(OpenApiDefaultResolver {
                capabilities: parsed.iter().map(info).collect(),
                filter,
            })),
        ),
    }
}

struct OpenApiDefaultResolver {
    capabilities: Vec<AgentOpenApiCapabilityInfo>,
    filter: Arc<dyn AgentOpenApiDefaultCapabilityFilter>,
}

#[async_trait]
impl AgentDefaultHostCapabilitiesResolver for OpenApiDefaultResolver {
    async fn resolve(&self, context: AgentDefaultHostCapabilitiesContext) -> Vec<String> {
        let mut pending = tokio::task::JoinSet::new();
        for (index, capability) in self.capabilities.iter().cloned().enumerate() {
            let filter = self.filter.clone();
            let context = context.clone();
            pending.spawn(async move {
                let include = filter.include(capability.clone(), &context).await;
                (index, capability.name, include)
            });
        }
        let mut included = Vec::new();
        while let Some(result) = pending.join_next().await {
            let (index, name, include) = result.expect("OpenAPI capability filter task panicked");
            if include {
                included.push((index, name));
            }
        }
        included.sort_by_key(|(index, _)| *index);
        included.into_iter().map(|(_, name)| name).collect()
    }
}

fn info(parsed: &ParsedCapability) -> AgentOpenApiCapabilityInfo {
    AgentOpenApiCapabilityInfo {
        name: parsed.capability.name.clone(),
        method: parsed.method.clone(),
        description: parsed.capability.description.clone(),
    }
}

fn info_string(spec: &Value, name: &str) -> Option<String> {
    spec.get("info")
        .and_then(|info| info.get(name))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_preset_derives_provider_defaults_strength_and_location() {
        let mut options = CreateAgentFromOpenApiOptions::new("https://upstream.example");
        options.default_host_capabilities = Some(AgentOpenApiDefaultCapabilities::Methods(vec![
            "GET".into(),
            "HEAD".into(),
        ]));
        options.approval_strength = Some(AgentOpenApiApprovalStrength::Methods(
            BTreeMap::from_iter([
                ("GET".into(), AgentApprovalStrength::None),
                ("POST".into(), AgentApprovalStrength::Webauthn),
            ]),
        ));
        options.location = Some("https://resource.example/agent/execute".into());
        let preset = create_preset(&super::super::test_support::fixture(), options);
        assert_eq!(preset.provider_name.as_deref(), Some("Message API"));
        assert_eq!(
            preset.provider_description.as_deref(),
            Some("Read and create messages")
        );
        assert_eq!(
            preset.default_host_capabilities,
            Some(vec!["messages.get".into()])
        );
        assert_eq!(
            preset
                .capabilities
                .iter()
                .map(|capability| (
                    capability.name.as_str(),
                    capability.approval_strength,
                    capability.location.as_deref()
                ))
                .collect::<Vec<_>>(),
            [
                (
                    "messages.get",
                    Some(AgentApprovalStrength::None),
                    Some("https://resource.example/agent/execute")
                ),
                (
                    "messages.create",
                    Some(AgentApprovalStrength::Webauthn),
                    Some("https://resource.example/agent/execute")
                )
            ]
        );
    }

    #[test]
    fn method_strength_map_leaves_unmapped_capabilities_unchanged() {
        let mut options = CreateAgentFromOpenApiOptions::new("https://upstream.example");
        options.approval_strength = Some(AgentOpenApiApprovalStrength::Methods(
            BTreeMap::from_iter([("GET".into(), AgentApprovalStrength::None)]),
        ));
        let preset = create_preset(&super::super::test_support::fixture(), options);
        assert_eq!(
            preset.capabilities[0].approval_strength,
            Some(AgentApprovalStrength::None)
        );
        assert_eq!(preset.capabilities[1].approval_strength, None);
    }
}
