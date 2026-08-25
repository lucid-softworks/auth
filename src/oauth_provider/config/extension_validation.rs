fn validate_extensions(config: &OAuthProviderConfig) -> Result<(), OAuthProviderConfigError> {
    let mut grants = BTreeSet::new();
    let mut methods = BTreeSet::new();
    let mut assertions = BTreeSet::new();
    let mut discoveries = BTreeSet::new();
    for extension in &config.extensions {
        for grant in extension.grant_types() {
            validate_extension_uri("grant type", &grant, None)?;
            unique_extension_key("grant type", grant, &mut grants)?;
        }
        for method in extension.client_authentication_methods() {
            let reserved = [
                "none",
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
            ];
            if method.method.trim().is_empty() || reserved.contains(&method.method.as_str()) {
                return Err(OAuthProviderConfigError::InvalidExtension(format!(
                    "token_endpoint_auth_method is empty or reserved: {}",
                    method.method
                )));
            }
            unique_extension_key(
                "token_endpoint_auth_method",
                method.method.clone(),
                &mut methods,
            )?;
            if method.assertion_types.is_empty() {
                return Err(OAuthProviderConfigError::InvalidExtension(format!(
                    "client_assertion_type list cannot be empty for {}",
                    method.method
                )));
            }
            for assertion in method.assertion_types {
                validate_extension_uri(
                    "client_assertion_type",
                    &assertion,
                    Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                )?;
                unique_extension_key("client_assertion_type", assertion, &mut assertions)?;
            }
        }
        for discovery in extension.client_discovery_ids() {
            if discovery.trim().is_empty() {
                return Err(OAuthProviderConfigError::InvalidExtension(
                    "client discovery id cannot be empty".into(),
                ));
            }
            unique_extension_key("client discovery id", discovery, &mut discoveries)?;
        }
    }
    Ok(())
}
fn validate_extension_uri(
    label: &str,
    value: &str,
    reserved: Option<&str>,
) -> Result<(), OAuthProviderConfigError> {
    if reserved == Some(value) || url::Url::parse(value).is_err() {
        return Err(OAuthProviderConfigError::InvalidExtension(format!(
            "{label} must be a non-reserved absolute URI: {value}"
        )));
    }
    Ok(())
}

fn unique_extension_key(
    label: &str,
    value: String,
    seen: &mut BTreeSet<String>,
) -> Result<(), OAuthProviderConfigError> {
    if !seen.insert(value.clone()) {
        return Err(OAuthProviderConfigError::InvalidExtension(format!(
            "extensions register {label} {value:?} more than once"
        )));
    }
    Ok(())
}
