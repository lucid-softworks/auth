use lucid_auth::{AuthConfig, CookieCacheStrategy};

pub(super) fn configure(config: &mut AuthConfig) {
    config.session.cookie_cache.enabled = true;
    config.session.cookie_cache.strategy = match std::env::var("LUCID_AUTH_COOKIE_CACHE_STRATEGY")
        .as_deref()
    {
        Ok("jwt") => CookieCacheStrategy::Jwt,
        Ok("jwe") => CookieCacheStrategy::Jwe,
        _ => CookieCacheStrategy::Compact,
    };
}
