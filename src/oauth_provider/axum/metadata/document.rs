use serde_json::{Map, Value, json};

use crate::{
    AuthService,
    oauth_provider::{
        OAuthProviderConfig, OAuthProviderMetadataDocument, config::DEFAULT_DPOP_ALGORITHMS,
    },
};

pub(super) fn provider_metadata(
    base_url: String,
    service: &AuthService,
    config: &OAuthProviderConfig,
    oidc: bool,
) -> Value {
    let jwt = (!config.disable_jwt_plugin)
        .then(|| service.jwt())
        .flatten();
    let issuer = jwt
        .as_ref()
        .and_then(|jwt| jwt.configured_issuer())
        .unwrap_or(&base_url);
    let issuer = crate::oauth_provider::issuer::normalize_issuer(issuer);
    let mut metadata = discovery_metadata(config);
    metadata.extend(core_metadata(&base_url, &issuer, config));
    add_optional_endpoints(&mut metadata, &base_url, config, jwt.as_ref());
    if oidc {
        add_oidc_metadata(&mut metadata, &base_url, config, jwt.as_ref());
    }
    apply_extensions(
        &mut metadata,
        config,
        if oidc {
            OAuthProviderMetadataDocument::OpenIdConnect
        } else {
            OAuthProviderMetadataDocument::AuthorizationServer
        },
    );
    Value::Object(metadata)
}

fn core_metadata(base_url: &str, issuer: &str, config: &OAuthProviderConfig) -> Map<String, Value> {
    let mut metadata = endpoint_metadata(base_url, issuer);
    metadata.extend(protocol_metadata(config));
    metadata.extend(authentication_metadata(config));
    metadata
}

fn endpoint_metadata(base_url: &str, issuer: &str) -> Map<String, Value> {
    Map::from_iter([
        ("issuer".into(), json!(issuer)),
        (
            "authorization_endpoint".into(),
            json!(format!("{base_url}/oauth2/authorize")),
        ),
        (
            "token_endpoint".into(),
            json!(format!("{base_url}/oauth2/token")),
        ),
        (
            "revocation_endpoint".into(),
            json!(format!("{base_url}/oauth2/revoke")),
        ),
        (
            "introspection_endpoint".into(),
            json!(format!("{base_url}/oauth2/introspect")),
        ),
    ])
}

fn protocol_metadata(config: &OAuthProviderConfig) -> Map<String, Value> {
    Map::from_iter([
        ("scopes_supported".into(), advertised_scopes(config)),
        (
            "response_types_supported".into(),
            if config
                .grant_types
                .iter()
                .any(|grant| grant == "authorization_code")
            {
                json!(["code"])
            } else {
                json!([])
            },
        ),
        ("response_modes_supported".into(), json!(["query"])),
        (
            "grant_types_supported".into(),
            json!(extension_grants(config)),
        ),
        ("code_challenge_methods_supported".into(), json!(["S256"])),
        (
            "authorization_response_iss_parameter_supported".into(),
            json!(true),
        ),
        (
            "dpop_signing_alg_values_supported".into(),
            json!(dpop_algorithms(config)),
        ),
        (
            "backchannel_logout_supported".into(),
            json!(!config.disable_jwt_plugin),
        ),
        (
            "backchannel_logout_session_supported".into(),
            json!(!config.disable_jwt_plugin),
        ),
    ])
}

fn authentication_metadata(config: &OAuthProviderConfig) -> Map<String, Value> {
    let signing_algorithms = private_key_jwt_algorithms();
    Map::from_iter([
        (
            "token_endpoint_auth_methods_supported".into(),
            Value::Array(extension_auth_methods(config, true)),
        ),
        (
            "token_endpoint_auth_signing_alg_values_supported".into(),
            signing_algorithms.clone(),
        ),
        (
            "revocation_endpoint_auth_methods_supported".into(),
            Value::Array(extension_auth_methods(config, false)),
        ),
        (
            "revocation_endpoint_auth_signing_alg_values_supported".into(),
            signing_algorithms.clone(),
        ),
        (
            "introspection_endpoint_auth_methods_supported".into(),
            Value::Array(extension_auth_methods(config, false)),
        ),
        (
            "introspection_endpoint_auth_signing_alg_values_supported".into(),
            signing_algorithms,
        ),
    ])
}

fn advertised_scopes(config: &OAuthProviderConfig) -> Value {
    json!(
        config
            .advertised_metadata
            .scopes_supported
            .as_ref()
            .unwrap_or(&config.scopes)
    )
}

fn extension_auth_methods(config: &OAuthProviderConfig, include_none: bool) -> Vec<Value> {
    let mut methods = vec![
        Value::String("client_secret_basic".into()),
        Value::String("client_secret_post".into()),
        Value::String("private_key_jwt".into()),
    ];
    if include_none
        && (config.allow_unauthenticated_client_registration
            || config
                .extensions
                .iter()
                .any(|extension| !extension.client_discovery_ids().is_empty()))
    {
        methods.insert(0, Value::String("none".into()));
    }
    for method in config
        .extensions
        .iter()
        .flat_map(|extension| extension.client_authentication_methods())
    {
        if !methods.iter().any(|value| value == &method.method) {
            methods.push(Value::String(method.method));
        }
    }
    methods
}

fn extension_grants(config: &OAuthProviderConfig) -> Vec<String> {
    let mut grant_types = config.grant_types.clone();
    for grant in config
        .extensions
        .iter()
        .flat_map(|extension| extension.grant_types())
    {
        if !grant_types.contains(&grant) {
            grant_types.push(grant);
        }
    }
    grant_types
}

fn apply_extensions(
    metadata: &mut Map<String, Value>,
    config: &OAuthProviderConfig,
    document: OAuthProviderMetadataDocument,
) {
    let base = metadata.clone();
    for extension in &config.extensions {
        for (name, value) in extension.server_metadata(document, &base) {
            metadata.entry(name).or_insert(value);
        }
    }
}

fn discovery_metadata(config: &OAuthProviderConfig) -> Map<String, Value> {
    let mut metadata = Map::new();
    for extension in &config.extensions {
        metadata.extend(extension.client_discovery_metadata());
    }
    metadata
}

fn add_optional_endpoints(
    metadata: &mut Map<String, Value>,
    issuer: &str,
    config: &OAuthProviderConfig,
    jwt: Option<&crate::jwt::JwtService<'_>>,
) {
    if config.allow_dynamic_client_registration {
        metadata.insert(
            "registration_endpoint".into(),
            json!(format!("{issuer}/oauth2/register")),
        );
    }
    if let Some(jwt) = jwt {
        metadata.insert("jwks_uri".into(), json!(jwt.jwks_uri(issuer)));
    }
}

fn add_oidc_metadata(
    metadata: &mut Map<String, Value>,
    issuer: &str,
    config: &OAuthProviderConfig,
    jwt: Option<&crate::jwt::JwtService<'_>>,
) {
    let claims = config
        .advertised_metadata
        .claims_supported
        .clone()
        .unwrap_or_else(|| supported_claims(config));
    metadata.extend([
        (
            "userinfo_endpoint".into(),
            json!(format!("{issuer}/oauth2/userinfo")),
        ),
        (
            "end_session_endpoint".into(),
            json!(format!("{issuer}/oauth2/end-session")),
        ),
        (
            "subject_types_supported".into(),
            if config.pairwise_secret.is_some() {
                json!(["public", "pairwise"])
            } else {
                json!(["public"])
            },
        ),
        ("claims_supported".into(), json!(claims)),
        ("claims_parameter_supported".into(), json!(true)),
        ("acr_values_supported".into(), json!(["0"])),
        (
            "id_token_signing_alg_values_supported".into(),
            json!(
                jwt.map(|jwt| jwt.signing_algorithms())
                    .unwrap_or_else(|| vec!["HS256"])
            ),
        ),
        ("request_parameter_supported".into(), json!(false)),
        ("request_uri_parameter_supported".into(), json!(false)),
        (
            "prompt_values_supported".into(),
            json!(["login", "consent", "create", "select_account", "none"]),
        ),
    ]);
}

fn private_key_jwt_algorithms() -> Value {
    json!([
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"
    ])
}

fn dpop_algorithms(config: &OAuthProviderConfig) -> Vec<String> {
    if config.dpop.signing_algorithms.is_empty() {
        DEFAULT_DPOP_ALGORITHMS
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    } else {
        config.dpop.signing_algorithms.clone()
    }
}

fn supported_claims(config: &OAuthProviderConfig) -> Vec<String> {
    let mut claims = ["sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if config.scopes.iter().any(|scope| scope == "profile") {
        claims.extend(
            ["name", "picture", "given_name", "family_name"]
                .into_iter()
                .map(str::to_owned),
        );
    }
    if config.scopes.iter().any(|scope| scope == "email") {
        claims.extend(["email", "email_verified"].into_iter().map(str::to_owned));
    }
    claims
}
