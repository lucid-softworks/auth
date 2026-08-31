use super::*;

impl AuthService {
    pub(crate) fn dash_plugin(&self) -> Option<&crate::DashPlugin> {
        self.plugins.find::<crate::DashPlugin>()
    }

    pub(crate) fn dash_config_snapshot(&self) -> Value {
        let config = &self.config;
        let user_fields = config
            .user
            .additional_fields
            .iter()
            .map(|(name, field)| dash_field(name, field))
            .collect::<Vec<_>>();
        json!({
            "version": crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            "socialProviders": config.social_providers.iter().map(|provider| provider.id()).collect::<Vec<_>>(),
            "emailAndPassword": {
                "enabled": config.email_and_password.enabled,
                "disableSignUp": config.email_and_password.disable_sign_up,
                "autoSignIn": config.email_and_password.auto_sign_in,
                "requireEmailVerification": config.email_and_password.require_email_verification,
                "minPasswordLength": config.email_and_password.min_password_length,
                "maxPasswordLength": config.email_and_password.max_password_length,
            },
            "plugins": dash_plugins(self),
            "organization": {
                "sendInvitationEmailEnabled": false,
                "additionalFields": [],
            },
            "user": {
                "fields": [],
                "additionalFields": user_fields,
                "deleteUserEnabled": config.user.delete_user.enabled,
                "modelName": config.user.model_name,
            },
            "baseURL": config.base_url.as_ref().map(ToString::to_string),
            "basePath": config.base_path,
            "emailVerification": {
                "sendVerificationEmailEnabled": config.email_verification.sender.is_some(),
            },
            "insights": dash_insights(config),
        })
    }
}

fn dash_plugins(service: &AuthService) -> Vec<Value> {
    service
        .plugins
        .plugins()
        .iter()
        .zip(service.plugins.descriptors())
        .map(|(plugin, descriptor)| {
            let mut output = Map::new();
            output.insert("id".into(), Value::String(descriptor.id.into()));
            output.insert("schema".into(), dash_plugin_schema(plugin.schema()));
            output.insert("version".into(), Value::String(descriptor.version.into()));
            if let Some(dash) = plugin.as_any().downcast_ref::<crate::DashPlugin>() {
                output.insert("options".into(), dash_plugin_options(dash));
            }
            Value::Object(output)
        })
        .collect()
}

fn dash_plugin_schema(tables: Vec<crate::PluginSchemaTable>) -> Value {
    let mut schema = Map::new();
    for table in tables {
        let fields = table
            .fields
            .iter()
            .map(|(name, field)| {
                let mut value = dash_field(name, field);
                value
                    .as_object_mut()
                    .expect("field config is an object")
                    .remove("name");
                (name.clone(), value)
            })
            .collect::<Map<_, _>>();
        let mut value = json!({"fields": fields});
        if let Some(model_name) = table.model_name {
            value
                .as_object_mut()
                .expect("table config is an object")
                .insert("modelName".into(), Value::String(model_name));
        }
        schema.insert(table.logical_name, value);
    }
    Value::Object(schema)
}

fn dash_plugin_options(plugin: &crate::DashPlugin) -> Value {
    let connection = plugin.resolved_connection();
    let activity = plugin.options().activity_tracking;
    let managed = &plugin.options().managed_directory_sync;
    json!({
        "apiUrl": connection.api_url,
        "kvUrl": connection.kv_url,
        "apiKey": "[REDACTED]",
        "apiOptions": {"timeout": connection.api_timeout.as_millis()},
        "kvOptions": {
            "timeout": connection.kv_timeout.as_millis(),
            "retry": {
                "attempts": connection.kv_retry.attempts,
                "baseDelay": connection.kv_retry.base_delay.as_millis(),
                "maxDelay": connection.kv_retry.max_delay.as_millis(),
            },
        },
        "activityTracking": {
            "enabled": activity.enabled,
            "updateInterval": activity.update_interval.as_millis(),
        },
        "managedDirectorySync": {
            "enabled": managed.enabled,
            "ssoPairing": managed.sso_pairing,
            "membershipProjection": {
                "enabled": managed.membership_projection.enabled,
                "role": managed.membership_projection.role,
            },
        },
    })
}

fn dash_insights(config: &crate::AuthConfig) -> Value {
    let entropy = if config.secret == b"better-auth-secret-12345678901234567890"
        || config.secret.len() < 32
    {
        0.0
    } else {
        estimate_entropy(&config.secret)
    };
    json!({
        "hasDatabase": true,
        "cookies": Value::Null,
        "hasIpAddressHeaders": !config.ip_address.ip_address_headers.is_empty(),
        "ipAddressHeaders": (!config.ip_address.ip_address_headers.is_empty()).then_some(&config.ip_address.ip_address_headers),
        "disableIpTracking": config.ip_address.disable_ip_tracking,
        "disableCSRFCheck": false,
        "disableOriginCheck": false,
        "allowDifferentEmails": config.account.account_linking.enabled && config.account.account_linking.allow_different_emails,
        "identityStrategy": "issuer",
        "skipStateCookieCheck": config.account.skip_state_cookie_check,
        "storeStateCookieStrategy": match config.account.store_state_strategy { crate::OAuthStateStrategy::Database => "database", crate::OAuthStateStrategy::Cookie => "cookie" },
        "cookieCache": {
            "enabled": config.session.cookie_cache.enabled,
            "strategy": config.session.cookie_cache.enabled.then_some(match config.session.cookie_cache.strategy { crate::CookieCacheStrategy::Compact => "compact", crate::CookieCacheStrategy::Jwt => "jwt", crate::CookieCacheStrategy::Jwe => "jwe" }),
            "refreshCache": config.session.cookie_cache.enabled.then_some(!matches!(config.session.cookie_cache.refresh_cache, crate::CookieCacheRefresh::Disabled)),
        },
        "sessionFreshAge": config.session_fresh_age.num_seconds(),
        "disableVerificationCleanup": config.verification.disable_cleanup,
        "minPasswordLength": config.email_and_password.enabled.then_some(config.email_and_password.min_password_length),
        "maxPasswordLength": config.email_and_password.enabled.then_some(config.email_and_password.max_password_length),
        "hasRateLimitDisabled": !config.rate_limit.enabled,
        "rateLimitStorage": Value::Null,
        "storeSessionInDatabase": config.session.store_session_in_database,
        "preserveSessionInDatabase": config.session.preserve_session_in_database,
        "secretEntropy": entropy,
        "useSecureCookies": config.use_secure_cookies,
        "crossSubDomainCookiesEnabled": config.cookies.cross_subdomain_enabled(),
        "crossSubDomainCookiesDomain": config.cookies.cross_subdomain_domain(),
        "defaultCookieAttributes": Value::Null,
        "appName": Value::Null,
        "hasJoinsEnabled": false,
        "hasErrorURLConfigured": false,
    })
}
