mod domain;
mod callback;
mod management;
mod mutation;
mod registration;
mod runtime_oidc;
mod saml_metadata;
mod sanitize;
mod sign_in;
mod support;

use super::SsoPlugin;
use crate::{AuthService, AxumPluginRoute};
use axum::{Extension, routing::get};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    plugin: Arc<SsoPlugin>,
) -> Vec<AxumPluginRoute> {
    let mut routes = vec![
        AxumPluginRoute::new(
            "/sign-in/sso",
            axum::routing::post(sign_in::sign_in).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/callback/{provider_id}",
            get(callback::provider).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/callback",
            get(callback::shared).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/saml2/sp/metadata",
            get(saml_metadata::metadata).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/providers",
            get(management::list).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/get-provider",
            get(management::get).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/register",
            axum::routing::post(registration::register).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/update-provider",
            axum::routing::post(mutation::update).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/delete-provider",
            axum::routing::post(mutation::delete).layer(Extension(plugin.clone())),
        ),
    ];
    if plugin.options().domain_verification {
        routes.push(AxumPluginRoute::new(
            "/sso/request-domain-verification",
            axum::routing::post(domain::request).layer(Extension(plugin.clone())),
        ));
        routes.push(AxumPluginRoute::new(
            "/sso/verify-domain",
            axum::routing::post(domain::verify).layer(Extension(plugin)),
        ));
    }
    routes
}
