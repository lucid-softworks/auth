mod body;
mod common;
mod features;
mod portal;
mod projection;
mod seats;
mod subscriptions;
mod usage;

use crate::{
    AxumPluginRoute,
    commet::{CommetFeatureKind, CommetPlugin},
};
use axum::{Extension, routing::MethodRouter};
use std::{collections::BTreeSet, sync::Arc};

pub(super) fn routes(
    _service: Arc<crate::AuthService>,
    plugin: CommetPlugin,
) -> Vec<AxumPluginRoute> {
    let layer =
        |route: MethodRouter| route.layer::<_, std::convert::Infallible>(Extension(plugin.clone()));
    let mut routes = Vec::new();
    let mut installed = BTreeSet::new();

    for feature in &plugin.options().features {
        let kind = feature.kind();
        if !installed.insert(kind) {
            continue;
        }
        match kind {
            CommetFeatureKind::Portal => routes.extend(portal::routes(&layer)),
            CommetFeatureKind::Subscriptions => routes.extend(subscriptions::routes(&layer)),
            CommetFeatureKind::Features => routes.extend(features::routes(&layer)),
            CommetFeatureKind::Usage => routes.extend(usage::routes(&layer)),
            CommetFeatureKind::Seats => routes.extend(seats::routes(&layer)),
            CommetFeatureKind::Webhooks => {}
        }
    }
    routes
}
