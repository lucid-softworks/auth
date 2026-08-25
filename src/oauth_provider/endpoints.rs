use crate::{PluginEndpoint, PluginHttpMethod, PluginRateLimit};
use std::borrow::Cow;

macro_rules! endpoint {
    ($method:ident, $path:literal, $client_method:literal) => {
        PluginEndpoint {
            method: PluginHttpMethod::$method,
            path: Cow::Borrowed($path),
            client_method: $client_method,
        }
    };
}

/// Better Auth 1.7.1 OAuth Provider endpoint surface.
///
/// Endpoints accepting more than one method have one descriptor per method so
/// hosts can register and authorize each wire operation independently.
pub const OAUTH_PROVIDER_ENDPOINTS: &[PluginEndpoint] = &[
    endpoint!(
        Get,
        "/.well-known/oauth-authorization-server",
        "getOAuthServerConfig"
    ),
    endpoint!(Get, "/.well-known/openid-configuration", "getOpenIdConfig"),
    endpoint!(Get, "/oauth2/authorize", "oauth2Authorize"),
    endpoint!(Post, "/oauth2/authorize", "oauth2Authorize"),
    endpoint!(Post, "/oauth2/consent", "oauth2Consent"),
    endpoint!(Post, "/oauth2/continue", "oauth2Continue"),
    endpoint!(Post, "/oauth2/token", "oauth2Token"),
    endpoint!(Post, "/oauth2/introspect", "oauth2Introspect"),
    endpoint!(Post, "/oauth2/revoke", "oauth2Revoke"),
    endpoint!(Get, "/oauth2/userinfo", "oauth2UserInfo"),
    endpoint!(Post, "/oauth2/userinfo", "oauth2UserInfo"),
    endpoint!(Get, "/oauth2/end-session", "oauth2EndSession"),
    endpoint!(Post, "/oauth2/end-session", "oauth2EndSession"),
    endpoint!(
        Post,
        "/oauth2/end-session/confirm",
        "oauth2EndSessionConfirmation"
    ),
    endpoint!(Post, "/oauth2/register", "registerOAuthClient"),
    endpoint!(
        Post,
        "/admin/oauth2/create-client",
        "adminCreateOAuthClient"
    ),
    endpoint!(Post, "/oauth2/create-client", "createOAuthClient"),
    endpoint!(Get, "/oauth2/get-client", "getOAuthClient"),
    endpoint!(Get, "/oauth2/public-client", "getOAuthClientPublic"),
    endpoint!(
        Post,
        "/oauth2/public-client-prelogin",
        "getOAuthClientPublicPrelogin"
    ),
    endpoint!(Get, "/oauth2/get-clients", "getOAuthClients"),
    endpoint!(
        Patch,
        "/admin/oauth2/update-client",
        "adminUpdateOAuthClient"
    ),
    endpoint!(Post, "/oauth2/update-client", "updateOAuthClient"),
    endpoint!(Post, "/oauth2/client/rotate-secret", "rotateClientSecret"),
    endpoint!(Post, "/oauth2/delete-client", "deleteOAuthClient"),
    endpoint!(Get, "/oauth2/get-consent", "getOAuthConsent"),
    endpoint!(Get, "/oauth2/get-consents", "getOAuthConsents"),
    endpoint!(Post, "/oauth2/update-consent", "updateOAuthConsent"),
    endpoint!(Post, "/oauth2/delete-consent", "deleteOAuthConsent"),
    endpoint!(Post, "/admin/oauth2/resources", "adminCreateOAuthResource"),
    endpoint!(Get, "/admin/oauth2/resources", "adminListOAuthResources"),
    endpoint!(
        Get,
        "/admin/oauth2/resources/:identifier",
        "adminGetOAuthResource"
    ),
    endpoint!(
        Patch,
        "/admin/oauth2/resources/:identifier",
        "adminUpdateOAuthResource"
    ),
    endpoint!(
        Delete,
        "/admin/oauth2/resources/:identifier",
        "adminDeleteOAuthResource"
    ),
    endpoint!(
        Post,
        "/admin/oauth2/resources/:identifier/clients/:client_id",
        "adminLinkClientResource"
    ),
    endpoint!(
        Delete,
        "/admin/oauth2/resources/:identifier/clients/:client_id",
        "adminUnlinkClientResource"
    ),
];

pub const DEFAULT_OAUTH_PROVIDER_RATE_LIMITS: &[PluginRateLimit] = &[
    PluginRateLimit {
        path: "/oauth2/token",
        window: 60,
        max: 20,
    },
    PluginRateLimit {
        path: "/oauth2/authorize",
        window: 60,
        max: 30,
    },
    PluginRateLimit {
        path: "/oauth2/introspect",
        window: 60,
        max: 100,
    },
    PluginRateLimit {
        path: "/oauth2/revoke",
        window: 60,
        max: 30,
    },
    PluginRateLimit {
        path: "/oauth2/register",
        window: 60,
        max: 5,
    },
    PluginRateLimit {
        path: "/oauth2/userinfo",
        window: 60,
        max: 60,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_matches_the_pinned_provider_surface() {
        assert_eq!(OAUTH_PROVIDER_ENDPOINTS.len(), 36);
        assert!(OAUTH_PROVIDER_ENDPOINTS.iter().any(|endpoint| {
            endpoint.method == PluginHttpMethod::Patch
                && endpoint.path == "/admin/oauth2/resources/:identifier"
        }));
        assert!(OAUTH_PROVIDER_ENDPOINTS.iter().any(|endpoint| {
            endpoint.method == PluginHttpMethod::Post && endpoint.path == "/oauth2/token"
        }));
    }

    #[test]
    fn default_rate_limits_match_better_auth_1_7_1() {
        assert_eq!(DEFAULT_OAUTH_PROVIDER_RATE_LIMITS.len(), 6);
        assert_eq!(DEFAULT_OAUTH_PROVIDER_RATE_LIMITS[0].max, 20);
        assert_eq!(DEFAULT_OAUTH_PROVIDER_RATE_LIMITS[2].max, 100);
        assert_eq!(DEFAULT_OAUTH_PROVIDER_RATE_LIMITS[4].max, 5);
    }
}
