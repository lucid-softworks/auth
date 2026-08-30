mod discovery;
mod groups;
mod query;
mod support;
mod users;

use super::ScimPlugin;
use crate::{AuthService, AxumPluginRoute};
use axum::routing::get;
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    plugin: Arc<ScimPlugin>,
) -> Vec<AxumPluginRoute> {
    use axum::Extension;
    vec![
        AxumPluginRoute::new(
            "/scim/v2/Users",
            get(users::list).post(users::create).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/scim/v2/Users/{userId}",
            get(users::get)
                .put(users::replace)
                .patch(users::patch)
                .delete(users::delete)
                .layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/scim/v2/Groups",
            get(groups::list)
                .post(groups::create)
                .layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/scim/v2/Groups/{groupId}",
            get(groups::get)
                .put(groups::replace)
                .patch(groups::patch)
                .delete(groups::delete)
                .layer(Extension(plugin)),
        ),
        AxumPluginRoute::new(
            "/scim/v2/ServiceProviderConfig",
            get(discovery::service_provider_config),
        ),
        AxumPluginRoute::new("/scim/v2/Schemas", get(discovery::schemas)),
        AxumPluginRoute::new("/scim/v2/Schemas/{schemaId}", get(discovery::schema)),
        AxumPluginRoute::new(
            "/scim/v2/ResourceTypes",
            get(discovery::resource_types),
        ),
        AxumPluginRoute::new(
            "/scim/v2/ResourceTypes/{resourceTypeId}",
            get(discovery::resource_type),
        ),
    ]
}
