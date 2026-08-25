use crate::{OAuthProviderPluginConfig, OAuthResourceInput};
use std::net::{IpAddr, Ipv6Addr};

pub const DEFAULT_MCP_REFRESH_TOKEN_REUSE_INTERVAL: u64 = 30;

/// Better Auth MCP options: the complete OAuth Provider configuration plus
/// the canonical protected-resource identifier.
#[derive(Clone)]
pub struct McpPluginConfig {
    pub resource: String,
    pub oauth_provider: OAuthProviderPluginConfig,
    /// `None` selects MCP's 30-second default; `Some(0)` restores strict replay.
    pub refresh_token_reuse_interval: Option<u64>,
}

impl McpPluginConfig {
    pub fn new(resource: impl Into<String>, oauth_provider: OAuthProviderPluginConfig) -> Self {
        Self {
            resource: resource.into(),
            oauth_provider,
            refresh_token_reuse_interval: None,
        }
    }

    pub fn validate(&self) -> Result<(), McpPluginConfigError> {
        validate_mcp_resource(&self.resource).map(|_| ())
    }

    pub(crate) fn effective_oauth_provider(
        &self,
    ) -> Result<OAuthProviderPluginConfig, McpPluginConfigError> {
        let resource = validate_mcp_resource(&self.resource)?;
        let mut provider = self.oauth_provider.clone();
        provider.refresh_token_reuse_interval = self
            .refresh_token_reuse_interval
            .unwrap_or(DEFAULT_MCP_REFRESH_TOKEN_REUSE_INTERVAL);
        if !provider
            .resources
            .iter()
            .any(|configured| configured.identifier == resource)
        {
            provider.resources.push(OAuthResourceInput::from(resource));
        }
        if !provider
            .client_registration_default_resources
            .iter()
            .any(|configured| configured == resource)
        {
            provider
                .client_registration_default_resources
                .push(resource.into());
        }
        Ok(provider)
    }
}

impl std::fmt::Debug for McpPluginConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpPluginConfig")
            .field("resource", &self.resource)
            .field("oauth_provider", &self.oauth_provider)
            .field(
                "refresh_token_reuse_interval",
                &self.refresh_token_reuse_interval,
            )
            .finish()
    }
}

pub(crate) fn validate_mcp_resource(resource: &str) -> Result<&str, McpPluginConfigError> {
    let url = url::Url::parse(resource).map_err(|_| {
        McpPluginConfigError::InvalidResource("MCP resource must be an absolute URL")
    })?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(McpPluginConfigError::InvalidResource(
            "MCP resource URL must not contain credentials",
        ));
    }
    if resource.contains('#') {
        return Err(McpPluginConfigError::InvalidResource(
            "MCP resource URL must not contain a fragment",
        ));
    }
    if resource.contains('?') {
        return Err(McpPluginConfigError::InvalidResource(
            "MCP resource URL must not contain a query; to protect a query-carrying resource, verify tokens with verifyAccessTokenRequest and build challenges with createResourceServerChallenge",
        ));
    }
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback_host(&url)) {
        return Err(McpPluginConfigError::InvalidResource(
            "MCP resource URL must use HTTPS, except for localhost or loopback IP development URLs",
        ));
    }
    Ok(resource)
}

fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(address)) => address.octets()[0] == 127,
        Some(url::Host::Ipv6(address)) => address == Ipv6Addr::LOCALHOST,
        Some(url::Host::Domain(host)) => {
            host.parse::<IpAddr>().is_ok_and(|address| match address {
                IpAddr::V4(address) => address.octets()[0] == 127,
                IpAddr::V6(address) => address == Ipv6Addr::LOCALHOST,
            })
        }
        None => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpPluginConfigError {
    #[error("{0}")]
    InvalidResource(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(resource: &str) -> McpPluginConfig {
        McpPluginConfig::new(
            resource,
            OAuthProviderPluginConfig::new("/login", "/consent"),
        )
    }

    #[test]
    fn resource_validation_matches_the_pinned_mcp_rules() {
        for accepted in [
            "https://api.example.test/mcp",
            "http://localhost:3000/mcp",
            "http://127.42.0.9/mcp",
            "http://[::1]:3000/mcp",
        ] {
            assert_eq!(validate_mcp_resource(accepted), Ok(accepted));
        }
        for (resource, message) in [
            ("relative/mcp", "MCP resource must be an absolute URL"),
            (
                "https://user:secret@api.example.test/mcp",
                "MCP resource URL must not contain credentials",
            ),
            (
                "https://api.example.test/mcp#fragment",
                "MCP resource URL must not contain a fragment",
            ),
            (
                "https://api.example.test/mcp?tenant=one",
                "MCP resource URL must not contain a query; to protect a query-carrying resource, verify tokens with verifyAccessTokenRequest and build challenges with createResourceServerChallenge",
            ),
            (
                "http://api.example.test/mcp",
                "MCP resource URL must use HTTPS, except for localhost or loopback IP development URLs",
            ),
        ] {
            assert_eq!(
                config(resource).validate().unwrap_err().to_string(),
                message
            );
        }
    }

    #[test]
    fn composition_preserves_existing_resource_objects_and_uses_mcp_defaults() {
        let resource = "https://api.example.test/mcp";
        let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
        let mut existing = OAuthResourceInput::from(resource);
        existing.name = Some("Existing MCP resource".into());
        existing.dpop_bound_access_tokens_required = Some(true);
        provider.resources.push(existing.clone());
        provider
            .client_registration_default_resources
            .push(resource.into());
        let effective = config_with(provider, resource)
            .effective_oauth_provider()
            .unwrap();
        assert_eq!(effective.resources, vec![existing]);
        assert_eq!(
            effective.client_registration_default_resources,
            vec![resource]
        );
        assert_eq!(
            effective.refresh_token_reuse_interval,
            DEFAULT_MCP_REFRESH_TOKEN_REUSE_INTERVAL
        );
    }

    #[test]
    fn explicit_zero_restores_strict_refresh_replay() {
        let mut config = config("https://api.example.test/mcp");
        config.refresh_token_reuse_interval = Some(0);
        assert_eq!(
            config
                .effective_oauth_provider()
                .unwrap()
                .refresh_token_reuse_interval,
            0
        );
    }

    fn config_with(provider: OAuthProviderPluginConfig, resource: &str) -> McpPluginConfig {
        McpPluginConfig::new(resource, provider)
    }
}
