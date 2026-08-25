use async_trait::async_trait;
use axum::{http::HeaderValue, response::Response};
use lucid_auth::{
    AuthPlugin, AuthService, PluginDescriptor, PluginProvenance, PluginRequestContext,
};

pub(super) struct ResponseHeadersPlugin;

#[async_trait]
impl AuthPlugin for ResponseHeadersPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "bearer-response-fixture",
            display_name: "Bearer response fixture",
            version: "1.7.1",
            provenance: PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    async fn after_response(
        &self,
        _service: &AuthService,
        request: &PluginRequestContext,
        mut response: Response,
    ) -> Response {
        if request.path == "/sign-up/email" {
            response.headers_mut().insert(
                axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static("X-First, Set-Auth-Token"),
            );
            response
                .headers_mut()
                .insert("set-auth-token", HeaderValue::from_static("replaced"));
            response.headers_mut().append(
                axum::http::header::SET_COOKIE,
                HeaderValue::from_static("better-auth.session_token=last.value; Path=/"),
            );
        }
        response
    }

    fn contributes_on_response(&self) -> bool {
        true
    }
}
