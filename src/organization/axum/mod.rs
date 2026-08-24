use crate::{AuthService, AxumPluginRoute};
use std::sync::Arc;

mod invitation;
mod member;
mod member_list;
mod organization;
mod role;
mod team;

pub(super) fn routes(_service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
    let mut routes = organization::routes();
    routes.extend(invitation::routes());
    routes.extend(member::routes());
    if _service
        .organization_plugin()
        .is_ok_and(|plugin| plugin.config.teams.enabled)
    {
        routes.extend(team::routes());
    }
    if _service
        .organization_plugin()
        .is_ok_and(|plugin| plugin.config.dynamic_access_control.enabled)
    {
        routes.extend(role::routes());
    }
    routes
}
