use lucid_auth::{AuthConfig, RateLimitCustomRule};

pub(crate) fn configure(config: &mut AuthConfig) {
    config.rate_limit.enabled = true;
    config.rate_limit.custom_rules = vec![
        RateLimitCustomRule::limit("/native-plugin/rate-limit", 60, 2),
        RateLimitCustomRule::disabled("/**"),
    ];
}
