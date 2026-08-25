use super::{DUB_ADAPTER_VERSION, DubOptions};
use crate::{
    AuthPlugin, DatabaseHookContext, DatabaseRecord, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginRequestSecurity,
};
use std::{borrow::Cow, fmt, sync::Arc};

#[derive(Clone)]
pub struct DubPlugin {
    pub(crate) options: Arc<DubOptions>,
}

impl DubPlugin {
    pub fn new(options: DubOptions) -> Self {
        Self {
            options: Arc::new(options),
        }
    }

    pub fn options(&self) -> &DubOptions {
        &self.options
    }
}

impl fmt::Debug for DubPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DubPlugin")
            .field("options", &self.options)
            .finish()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for DubPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "dub",
            display_name: "Dub",
            version: DUB_ADAPTER_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(&[PluginEndpoint {
                method: PluginHttpMethod::Post,
                path: Cow::Borrowed("/dub/link"),
                client_method: "linkDub",
            }]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn request_security(&self, method: PluginHttpMethod, path: &str) -> PluginRequestSecurity {
        if method == PluginHttpMethod::Post && path == "/dub/link" {
            PluginRequestSecurity::CookieOrigin
        } else {
            PluginRequestSecurity::Browser
        }
    }

    fn request_origin_fields(
        &self,
        method: PluginHttpMethod,
        path: &str,
    ) -> &'static [&'static str] {
        if method == PluginHttpMethod::Post && path == "/dub/link" {
            &["callbackURL"]
        } else {
            &[]
        }
    }

    async fn after_database_create(
        &self,
        _service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), crate::AuthError> {
        let DatabaseRecord::User(user) = record else {
            return Ok(());
        };
        super::lifecycle::after_user_create(self.options.clone(), user, context).await
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DubLead, DubLeadError, FnDubLeadTracker};

    fn plugin() -> DubPlugin {
        DubPlugin::new(DubOptions::new(Arc::new(FnDubLeadTracker::new(
            |_: DubLead| async { Ok::<(), DubLeadError>(()) },
        ))))
    }

    #[test]
    fn descriptor_matches_the_exact_published_server_surface() {
        let plugin = plugin();
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "dub");
        assert_eq!(descriptor.version, "0.0.6");
        assert_eq!(descriptor.endpoints.len(), 1);
        assert_eq!(descriptor.endpoints[0].method, PluginHttpMethod::Post);
        assert_eq!(descriptor.endpoints[0].path, "/dub/link");
        assert_eq!(descriptor.endpoints[0].client_method, "linkDub");
        assert!(descriptor.client.is_none());
        assert!(descriptor.cookies.is_empty());
        assert!(descriptor.middleware.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        assert!(plugin.schema_fields().is_empty());
        assert!(plugin.migrations().is_empty());
    }

    #[test]
    fn link_route_selects_cookie_origin_security_and_callback_field() {
        let plugin = plugin();
        assert_eq!(
            plugin.request_security(PluginHttpMethod::Post, "/dub/link"),
            PluginRequestSecurity::CookieOrigin
        );
        assert_eq!(
            plugin.request_origin_fields(PluginHttpMethod::Post, "/dub/link"),
            ["callbackURL"]
        );
    }
}
