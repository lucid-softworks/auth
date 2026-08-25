use super::{DeviceAuthorizationConfig, DeviceAuthorizationStore};
use crate::AxumPluginRoute;
use axum::{
    Extension,
    routing::{get, post},
};
use std::sync::Arc;

mod code;
mod decision;
pub(super) mod error;
mod generation;
mod lookup;
mod redeem;
pub(super) mod request;
mod token;
pub(super) mod uri;
mod verify;

#[derive(Clone)]
struct DeviceAuthorizationState {
    config: Arc<DeviceAuthorizationConfig>,
    store: Arc<dyn DeviceAuthorizationStore>,
}

pub(super) fn routes(
    config: Arc<DeviceAuthorizationConfig>,
    store: Arc<dyn DeviceAuthorizationStore>,
) -> Vec<AxumPluginRoute> {
    let state = DeviceAuthorizationState { config, store };
    vec![
        route("/device/code", post(code::issue), &state),
        route("/device/token", post(token::exchange), &state),
        route("/device", get(verify::verify), &state),
        route("/device/approve", post(decision::approve), &state),
        route("/device/deny", post(decision::deny), &state),
    ]
}

fn route(
    path: &'static str,
    route: axum::routing::MethodRouter,
    state: &DeviceAuthorizationState,
) -> AxumPluginRoute {
    AxumPluginRoute::new(path, route.layer(Extension(state.clone())))
}
