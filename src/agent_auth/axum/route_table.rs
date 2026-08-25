use super::{AgentAuthState, agent, approval, auth, capability, discovery, host};
use crate::AxumPluginRoute;
use axum::{
    Extension, middleware,
    routing::{get, post},
};

pub(super) fn plugin_routes(state: AgentAuthState) -> Vec<AxumPluginRoute> {
    let mut routes = discovery_routes(&state);
    routes.extend(capability_routes(&state));
    routes.extend(agent_routes(&state));
    routes.extend(approval_routes(&state));
    routes.extend(host_routes(state));
    routes
}

fn discovery_routes(state: &AgentAuthState) -> Vec<AxumPluginRoute> {
    vec![AxumPluginRoute::new(
        "/agent-configuration",
        get(discovery::configuration).layer(Extension(state.clone())),
    )]
}

fn capability_routes(state: &AgentAuthState) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/capability/list",
            get(capability::list).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/capability/describe",
            get(capability::describe).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/capability/execute",
            post(capability::execute).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/capability/batch-execute",
            post(capability::batch_execute).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/agent/session",
            get(auth::session).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/agent/introspect",
            post(auth::introspect).layer(Extension(state.clone())),
        ),
    ]
}

fn agent_routes(state: &AgentAuthState) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/agent/register",
            post(agent::register).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new("/agent/list", guarded(get(agent::list), state)),
        AxumPluginRoute::new("/agent/get", guarded(get(agent::get), state)),
        AxumPluginRoute::new("/agent/update", guarded(post(agent::update), state)),
        AxumPluginRoute::new(
            "/agent/revoke",
            post(agent::revoke).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/agent/rotate-key",
            post(agent::rotate_key).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/agent/reactivate",
            post(agent::reactivate).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new("/agent/cleanup", guarded(post(agent::cleanup), state)),
        AxumPluginRoute::new(
            "/agent/status",
            get(agent::status).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/agent/claim",
            post(agent::claim).layer(Extension(state.clone())),
        ),
    ]
}

fn approval_routes(state: &AgentAuthState) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/agent/request-capability",
            post(approval::request_capability).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/agent/approve-capability",
            guarded(post(approval::approve_capability), state),
        ),
        AxumPluginRoute::new(
            "/agent/grant-capability",
            guarded(post(approval::grant_capability), state),
        ),
        AxumPluginRoute::new(
            "/agent/revoke-capability",
            post(approval::revoke_capability).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/agent/ciba/authorize",
            post(approval::ciba_authorize).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/agent/ciba/pending",
            guarded(get(approval::ciba_pending), state),
        ),
        AxumPluginRoute::new(
            "/agent/device/code",
            post(approval::device_code).layer(Extension(state.clone())),
        ),
    ]
}

fn host_routes(state: AgentAuthState) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/host/create", guarded(post(host::create), &state)),
        AxumPluginRoute::new("/host/enroll", guarded(post(host::enroll), &state)),
        AxumPluginRoute::new("/host/list", guarded(get(host::list), &state)),
        AxumPluginRoute::new("/host/get", guarded(get(host::get), &state)),
        AxumPluginRoute::new(
            "/host/revoke",
            post(host::revoke).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new(
            "/host/switch-account",
            guarded(post(host::switch_account), &state),
        ),
        AxumPluginRoute::new("/host/update", guarded(post(host::update), &state)),
        AxumPluginRoute::new(
            "/host/rotate-key",
            post(host::rotate_key).layer(Extension(state)),
        ),
    ]
}

fn guarded(
    route: axum::routing::MethodRouter,
    state: &AgentAuthState,
) -> axum::routing::MethodRouter {
    route
        .layer::<_, std::convert::Infallible>(middleware::from_fn_with_state(
            state.clone(),
            auth::validate_before_hook,
        ))
        .layer(Extension(state.clone()))
}
