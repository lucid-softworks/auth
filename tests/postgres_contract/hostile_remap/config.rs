use lucid_auth::{AuthConfig, AuthError, RateLimitStorageMode};

pub(super) fn hostile_config() -> Result<AuthConfig, AuthError> {
    let mut config = AuthConfig::new([95; 32])?;
    config.email_and_password.enabled = true;

    config.user.model_name = Some("auth user".into());
    config.user.fields.name = mapped("display name");
    config.user.fields.email = mapped("login email");
    config.user.fields.email_verified = mapped("verified flag");
    config.user.fields.image = mapped("avatar url");
    config.user.fields.created_at = mapped("created at");
    config.user.fields.updated_at = mapped("updated at");

    config.session.model_name = Some("auth session".into());
    config.session.fields.expires_at = mapped("expires at");
    config.session.fields.token = mapped("session token");
    config.session.fields.created_at = mapped("created at");
    config.session.fields.updated_at = mapped("updated at");
    config.session.fields.ip_address = mapped("client ip");
    config.session.fields.user_agent = mapped("select");
    config.session.fields.user_id = mapped("owner id");

    config.account.model_name = Some("auth account".into());
    config.account.fields.issuer = mapped("issuer url");
    config.account.fields.account_id = mapped("remote id");
    config.account.fields.provider_id = mapped("provider name");
    config.account.fields.user_id = mapped("owner id");
    config.account.fields.access_token = mapped("access secret");
    config.account.fields.refresh_token = mapped("refresh secret");
    config.account.fields.id_token = mapped("identity token");
    config.account.fields.access_token_expires_at = mapped("access expires");
    config.account.fields.refresh_token_expires_at = mapped("refresh expires");
    config.account.fields.scope = mapped("granted scopes");
    config.account.fields.password = mapped("password digest");
    config.account.fields.created_at = mapped("created at");
    config.account.fields.updated_at = mapped("updated at");

    config.verification.model_name = Some("auth verification".into());
    config.verification.fields.identifier = mapped("lookup key");
    config.verification.fields.value = mapped("secret value");
    config.verification.fields.expires_at = mapped("expires at");
    config.verification.fields.created_at = mapped("created at");
    config.verification.fields.updated_at = mapped("updated at");

    config.rate_limit.storage = RateLimitStorageMode::Database;
    config.rate_limit.model_name = Some("request bucket".into());
    config.rate_limit.fields.key = mapped("limit key");
    config.rate_limit.fields.count = mapped("hit count");
    config.rate_limit.fields.last_request = mapped("last request ms");
    Ok(config)
}

fn mapped(value: &str) -> Option<String> {
    Some(value.into())
}
