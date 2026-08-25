use super::{AgentAuthState, AgentRequestContext};
use crate::{AgentHost, AgentIdentity, AgentSessionUser};

pub(super) async fn resolve_autonomous_user(
    state: &AgentAuthState,
    request: &AgentRequestContext<'_>,
    agent: &AgentIdentity,
    host: Option<&AgentHost>,
) -> Option<AgentSessionUser> {
    let resolver = state.config.resolve_autonomous_user.as_ref()?;
    resolver
        .resolve(crate::AgentAutonomousUserContext {
            endpoint: crate::AgentEndpointContext {
                method: request.method.to_owned(),
                path: request.path.to_owned(),
                base_url: request.base_url.to_owned(),
                headers: request
                    .headers
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.as_str().to_owned(), value.to_owned()))
                    })
                    .collect(),
            },
            host_id: agent.host_id.clone(),
            host_name: host.and_then(|host| host.name.clone()),
            agent_id: agent.id.clone(),
            agent_mode: agent.mode,
        })
        .await
}
