use super::{AgentAuthConfig, AgentAuthStore};
use crate::{AuthService, AxumPluginRoute, OrganizationStore};
use axum::{Extension, routing::get};
use std::sync::Arc;

mod agent;
mod approval;
mod auth;
mod capability;
mod discovery;
mod events;
mod host;
mod input;
mod route_table;

#[derive(Clone)]
struct AgentAuthState {
    config: Arc<AgentAuthConfig>,
    store: Arc<dyn AgentAuthStore>,
    organization_store: Option<Arc<dyn OrganizationStore>>,
    host_auth: host::HostAuthState,
    verifier: Arc<super::jwt::AgentJwtVerifier>,
}

pub(super) fn routes(
    config: Arc<AgentAuthConfig>,
    store: Arc<dyn AgentAuthStore>,
    service: Arc<AuthService>,
) -> Vec<AxumPluginRoute> {
    let verifier = runtime_verifier(&config, &service);
    let host_auth = host::HostAuthState::from_verifier(verifier.clone());
    let state = AgentAuthState {
        config,
        store,
        organization_store: organization_store(&service),
        host_auth,
        verifier,
    };
    route_table::plugin_routes(state)
}

pub(super) fn root_routes(
    config: Arc<AgentAuthConfig>,
    store: Arc<dyn AgentAuthStore>,
    service: Arc<AuthService>,
) -> Vec<AxumPluginRoute> {
    let verifier = runtime_verifier(&config, &service);
    let host_auth = host::HostAuthState::from_verifier(verifier.clone());
    vec![AxumPluginRoute::new(
        "/.well-known/agent-configuration",
        get(discovery::configuration).layer(Extension(AgentAuthState {
            config,
            store,
            organization_store: organization_store(&service),
            host_auth,
            verifier,
        })),
    )]
}

fn organization_store(service: &AuthService) -> Option<Arc<dyn OrganizationStore>> {
    service
        .organization_plugin()
        .ok()
        .map(|plugin| plugin.store.clone())
}

fn runtime_verifier(
    config: &AgentAuthConfig,
    service: &AuthService,
) -> Arc<super::jwt::AgentJwtVerifier> {
    let secondary = service.secondary_storage();
    let replay: Arc<dyn super::jwt::AgentJwtReplayStore> = match config.jti_cache_storage {
        super::AgentCacheStorage::SecondaryStorage if secondary.is_some() => Arc::new(
            super::jwt::SecondaryAgentJwtReplayStore::new(secondary.clone().expect("checked")),
        ),
        _ => Arc::new(super::jwt::MemoryAgentJwtReplayStore::default()),
    };
    let jwks = (config.jwks_cache_storage == super::AgentCacheStorage::SecondaryStorage)
        .then_some(secondary)
        .flatten();
    Arc::new(
        super::jwt::AgentJwtVerifier::with_jwks_storage(replay, jwks)
            .expect("Agent Auth JWT verifier configuration is valid"),
    )
}

#[cfg(test)]
fn memory_verifier() -> Arc<super::jwt::AgentJwtVerifier> {
    Arc::new(
        super::jwt::AgentJwtVerifier::new(Arc::new(
            super::jwt::MemoryAgentJwtReplayStore::default(),
        ))
        .unwrap(),
    )
}

fn issuer(service: &AuthService, headers: &axum::http::HeaderMap) -> String {
    crate::oauth_provider::axum::metadata::issuer(service, headers)
}
