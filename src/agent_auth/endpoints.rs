use crate::{PluginEndpoint, PluginHttpMethod};
use std::borrow::Cow;

const fn get(path: &'static str, client_method: &'static str) -> PluginEndpoint {
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: Cow::Borrowed(path),
        client_method,
    }
}

const fn post(path: &'static str, client_method: &'static str) -> PluginEndpoint {
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed(path),
        client_method,
    }
}

pub(super) const AGENT_AUTH_ENDPOINTS: &[PluginEndpoint] = &[
    get("/agent-configuration", "getAgentConfiguration"),
    get("/capability/list", "listCapabilities"),
    get("/capability/describe", "describeCapability"),
    post("/capability/execute", "executeCapability"),
    post("/capability/batch-execute", "batchExecuteCapability"),
    post("/agent/register", "register"),
    get("/agent/list", "listAgents"),
    get("/agent/get", "getAgent"),
    post("/agent/update", "updateAgent"),
    post("/agent/revoke", "revokeAgent"),
    post("/agent/revoke-capability", "revokeCapability"),
    post("/agent/rotate-key", "rotateKey"),
    post("/agent/reactivate", "reactivateAgent"),
    get("/agent/session", "getAgentSession"),
    post("/agent/cleanup", "cleanupAgents"),
    post("/agent/request-capability", "requestCapability"),
    post("/agent/approve-capability", "approveCapability"),
    get("/agent/status", "agentStatus"),
    post("/agent/introspect", "introspect"),
    post("/agent/grant-capability", "grantCapability"),
    post("/agent/claim", "claimAgent"),
    post("/agent/ciba/authorize", "cibaAuthorize"),
    get("/agent/ciba/pending", "cibaPending"),
    post("/agent/device/code", "deviceCode"),
    post("/host/create", "createHost"),
    post("/host/enroll", "enrollHost"),
    get("/host/list", "listHosts"),
    get("/host/get", "getHost"),
    post("/host/revoke", "revokeHost"),
    post("/host/switch-account", "switchHostAccount"),
    post("/host/update", "updateHost"),
    post("/host/rotate-key", "rotateHostKey"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn endpoint_surface_matches_agent_auth_0_6_2() {
        assert_eq!(AGENT_AUTH_ENDPOINTS.len(), 32);
        assert_eq!(
            AGENT_AUTH_ENDPOINTS
                .iter()
                .map(|endpoint| endpoint.path.as_ref())
                .collect::<BTreeSet<_>>()
                .len(),
            32
        );
        assert!(AGENT_AUTH_ENDPOINTS.iter().any(|endpoint| {
            endpoint.path == "/agent/device/code" && endpoint.method == PluginHttpMethod::Post
        }));
    }
}
