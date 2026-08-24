mod core;
mod member;

use crate::AxumPluginRoute;

pub(super) fn routes() -> Vec<AxumPluginRoute> {
    let mut routes = core::routes();
    routes.extend(member::routes());
    routes
}
