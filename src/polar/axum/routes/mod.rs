use super::PolarRouteState;
use crate::{AuthService, AxumPluginRoute};
use std::sync::Arc;

mod checkout;
mod customer;
mod usage;

pub(super) fn routes(_service: Arc<AuthService>, state: PolarRouteState) -> Vec<AxumPluginRoute> {
    let mut routes = Vec::new();
    if state.checkout.is_some() {
        routes.push(checkout::route(state.clone()));
    }
    if state.portal.is_some() {
        routes.extend(customer::routes(state.clone()));
    }
    if state.usage {
        routes.extend(usage::routes(state.clone()));
    }
    if let Some(webhook) = state.webhook {
        routes.push(super::webhook::route(webhook));
    }
    routes
}
