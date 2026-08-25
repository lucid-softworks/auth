mod input;
mod routes;
mod support;
mod webhook;

pub(crate) fn routes(
    service: std::sync::Arc<crate::AuthService>,
    plugin: crate::dodo_payments::DodoPaymentsPlugin,
) -> Vec<crate::AxumPluginRoute> {
    routes::routes(service, plugin)
}
