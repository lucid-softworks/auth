use crate::PluginHttpMethod;

pub(super) const CORE_ENDPOINTS: &[(PluginHttpMethod, &str)] = &[
    (PluginHttpMethod::Get, "/get-session"),
    (PluginHttpMethod::Post, "/sign-up/email"),
    (PluginHttpMethod::Post, "/sign-in/email"),
    (PluginHttpMethod::Post, "/verify-password"),
    (PluginHttpMethod::Post, "/request-password-reset"),
    (PluginHttpMethod::Get, "/reset-password/:token"),
    (PluginHttpMethod::Post, "/reset-password"),
    (PluginHttpMethod::Post, "/send-verification-email"),
    (PluginHttpMethod::Get, "/verify-email"),
    (PluginHttpMethod::Post, "/sign-out"),
    (PluginHttpMethod::Post, "/update-user"),
    (PluginHttpMethod::Post, "/update-session"),
    (PluginHttpMethod::Post, "/change-email"),
    (PluginHttpMethod::Post, "/delete-user"),
    (PluginHttpMethod::Get, "/delete-user/callback"),
    (PluginHttpMethod::Post, "/change-password"),
    (PluginHttpMethod::Get, "/list-sessions"),
    (PluginHttpMethod::Post, "/revoke-session"),
    (PluginHttpMethod::Post, "/revoke-other-sessions"),
    (PluginHttpMethod::Post, "/revoke-sessions"),
];
