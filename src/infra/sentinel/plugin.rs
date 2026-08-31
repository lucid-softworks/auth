use super::{SentinelOptions, SentinelSecurityClient, VERSION};
#[cfg(feature = "axum")]
use crate::infra::dash::IdentificationService;
use crate::infra::dash::IdentificationContext;
use crate::{
    AuthPlugin, PluginArtifactMetadata, PluginClientMetadata, PluginCookie, PluginDescriptor,
    PluginProvenance,
};
use async_trait::async_trait;
use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

const COOKIES: &[PluginCookie] = &[PluginCookie {
    name: "__infra-rid",
}];

#[derive(Clone)]
pub struct SentinelPlugin {
    options: Arc<SentinelOptions>,
    security: SentinelSecurityClient,
    #[cfg(feature = "axum")]
    identification: IdentificationService,
    request_identifications: Arc<Mutex<HashMap<String, IdentificationContext>>>,
    reservations: Arc<Mutex<HashMap<String, ReservationContext>>>,
}

#[derive(Clone, Debug)]
pub(super) struct ReservationContext {
    pub visitor_id: String,
    pub reservation_id: String,
    pub request_id: Option<String>,
}

impl SentinelPlugin {
    pub fn new(options: SentinelOptions) -> Self {
        let connection = options.connection.clone().resolve();
        let security = SentinelSecurityClient::from_resolved(
            connection.clone(),
            options.security.clone(),
        );
        #[cfg(feature = "axum")]
        let identification = IdentificationService::new(&connection);
        Self {
            options: Arc::new(options),
            security,
            #[cfg(feature = "axum")]
            identification,
            request_identifications: Arc::new(Mutex::new(HashMap::new())),
            reservations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn options(&self) -> &SentinelOptions {
        &self.options
    }

    pub fn security_client(&self) -> &SentinelSecurityClient {
        &self.security
    }

    #[cfg(feature = "axum")]
    pub(crate) fn identification_service(&self) -> &IdentificationService {
        &self.identification
    }

    pub(super) fn remember_identification(&self, context: &IdentificationContext) {
        if let Some(request_id) = context.request_id.as_ref() {
            self.request_identifications
                .lock()
                .expect("Sentinel request context lock is not poisoned")
                .insert(request_id.clone(), context.clone());
        }
    }

    pub(super) fn request_identification(&self, request_id: &str) -> Option<IdentificationContext> {
        self.request_identifications
            .lock()
            .expect("Sentinel request context lock is not poisoned")
            .get(request_id)
            .cloned()
    }

    pub(super) fn forget_identification(&self, request_id: Option<&str>) {
        if let Some(request_id) = request_id {
            self.request_identifications
                .lock()
                .expect("Sentinel request context lock is not poisoned")
                .remove(request_id);
        }
    }

    pub(super) fn remember_reservation(&self, request_id: String, context: ReservationContext) {
        self.reservations
            .lock()
            .expect("Sentinel reservation lock is not poisoned")
            .insert(request_id, context);
    }

    pub(super) fn take_reservation(&self, request_id: &str) -> Option<ReservationContext> {
        self.reservations
            .lock()
            .expect("Sentinel reservation lock is not poisoned")
            .remove(request_id)
    }

    /// Metadata for the separately published React Native/Expo client.
    pub fn native_client_metadata() -> PluginClientMetadata {
        PluginClientMetadata::official(
            "@better-auth/infra",
            "@better-auth/infra/native",
            "sentinelNativeClient",
        )
        .with_identity("sentinel", VERSION)
    }
}

impl Default for SentinelPlugin {
    fn default() -> Self {
        Self::new(SentinelOptions::default())
    }
}

impl fmt::Debug for SentinelPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SentinelPlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthPlugin for SentinelPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "sentinel",
            display_name: "Better Auth Infrastructure Sentinel",
            version: VERSION,
            provenance: PluginProvenance::PinnedBetterAuthPort {
                better_auth_version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                server: PluginArtifactMetadata::new(
                    "@better-auth/infra",
                    VERSION,
                    "@better-auth/infra",
                    "sentinel",
                ),
            },
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(&[]),
            cookies: COOKIES,
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@better-auth/infra",
                    "@better-auth/infra/client",
                    "sentinelClient",
                )
                .with_identity("sentinel", VERSION),
            ),
        }
    }

    fn database_hooks(&self) -> Option<&dyn crate::DatabaseHooks> {
        Some(self)
    }

    #[cfg(feature = "axum")]
    async fn on_request(
        &self,
        service: &crate::AuthService,
        request: axum::extract::Request,
    ) -> Result<axum::extract::Request, axum::response::Response> {
        super::axum::intercept(service, self, request).await
    }

    #[cfg(feature = "axum")]
    fn contributes_on_request(&self) -> bool {
        true
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: axum::response::Response,
    ) -> axum::response::Response {
        super::axum::after_response(service, self, request, response).await
    }

    #[cfg(feature = "axum")]
    fn contributes_on_response(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_the_exact_published_surfaces() {
        let descriptor = SentinelPlugin::default().descriptor();
        assert_eq!(descriptor.id, "sentinel");
        assert_eq!(descriptor.version, "0.4.3");
        assert!(descriptor.endpoints.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        assert_eq!(descriptor.cookies, COOKIES);

        let browser = descriptor.client.unwrap();
        assert_eq!(browser.factory, "sentinelClient");
        assert_eq!(browser.client_id, Some("sentinel"));
        let native = SentinelPlugin::native_client_metadata();
        assert_eq!(native.import_path, "@better-auth/infra/native");
        assert_eq!(native.factory, "sentinelNativeClient");
        assert_eq!(native.client_id, Some("sentinel"));
    }
}
