mod input;
mod routes;
mod support;

use crate::creem::{
    CreemOptions, CreemPlugin, CreemStore, CreemTransport, service::CreemStoreWebhookPersistence,
};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct CreemRouteState {
    pub options: Arc<CreemOptions>,
    pub store: Arc<dyn CreemStore>,
    pub transport: Arc<dyn CreemTransport>,
    pub webhook_persistence: Arc<CreemStoreWebhookPersistence>,
}

impl CreemRouteState {
    fn from_plugin(plugin: CreemPlugin) -> Self {
        Self {
            transport: plugin.options.transport(),
            webhook_persistence: Arc::new(CreemStoreWebhookPersistence::new(plugin.store.clone())),
            options: plugin.options,
            store: plugin.store,
        }
    }
}

pub(crate) fn routes(
    service: Arc<crate::AuthService>,
    plugin: CreemPlugin,
) -> Vec<crate::AxumPluginRoute> {
    routes::routes(service, CreemRouteState::from_plugin(plugin))
}
