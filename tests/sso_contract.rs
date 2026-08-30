use chrono::{TimeZone as _, Utc};
use lucid_auth::sso::{
    DEFAULT_CLOCK_SKEW_MS, DEFAULT_MAX_SAML_METADATA_SIZE, DEFAULT_MAX_SAML_RESPONSE_SIZE,
    DiscoveryErrorCode, OidcConfig, OidcDiscoveryDocument, REQUIRED_DISCOVERY_FIELDS,
    SamlConditions, SamlTimestampError, SamlTimestampOptions, SsoTokenEndpointAuthentication,
    compute_discovery_url, fetch_discovery_document, needs_runtime_discovery,
    normalize_discovery_urls, normalize_url, select_token_endpoint_auth_method,
    validate_discovery_document, validate_discovery_url, validate_oidc_endpoint_url,
    validate_saml_timestamp_at,
};
use lucid_auth::{
    AdditionalFieldType, AuthPlugin, MemorySsoStore, NewSsoProvider, PluginHttpMethod,
    PluginProvenance, SSO_VERSION, SsoOptions, SsoPlugin, SsoProviderUpdate, SsoStore,
    SsoStoreError,
};

#[test]
fn descriptor_matches_the_pinned_server_and_official_client() {
    let descriptor = SsoPlugin::default().descriptor();
    assert_eq!(descriptor.id, "sso");
    assert_eq!(descriptor.version, "1.7.1");
    assert_eq!(SSO_VERSION, "1.7.1");
    assert!(matches!(
        descriptor.provenance,
        PluginProvenance::PinnedBetterAuthPort { .. }
    ));
    assert_eq!(descriptor.endpoints.len(), 14);
    assert_eq!(
        descriptor
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.path == "/sso/saml2/sp/acs/:providerId")
            .map(|endpoint| endpoint.method)
            .collect::<Vec<_>>(),
        vec![PluginHttpMethod::Get, PluginHttpMethod::Post]
    );
    let client = descriptor.client.expect("official client metadata");
    assert_eq!(client.package, "@better-auth/sso");
    assert_eq!(client.import_path, "@better-auth/sso/client");
    assert_eq!(client.factory, "ssoClient");
    assert_eq!(client.client_id, Some("sso-client"));
    assert_eq!(client.path_methods.len(), 2);
}

#[test]
fn schema_and_domain_verification_are_conditional() {
    let plugin = SsoPlugin::default();
    let schema = plugin.schema();
    assert_eq!(schema.len(), 1);
    let provider = &schema[0];
    assert_eq!(provider.logical_name, "ssoProvider");
    assert_eq!(provider.model_name.as_deref(), Some("ssoProvider"));
    assert_eq!(provider.fields.len(), 7);
    assert!(!provider.fields.contains_key("domainVerified"));
    assert_eq!(
        provider.fields["oidcConfig"].field_type,
        AdditionalFieldType::String
    );
    assert!(!provider.fields["oidcConfig"].required);
    assert!(provider.fields["providerId"].unique);

    let enabled = SsoPlugin::new(SsoOptions {
        domain_verification: true,
    });
    let enabled_schema = enabled.schema();
    let verified = &enabled_schema[0].fields["domainVerified"];
    assert_eq!(verified.field_type, AdditionalFieldType::Boolean);
    assert!(!verified.required);
    assert_eq!(enabled.descriptor().endpoints.len(), 16);
}

#[test]
fn discovery_url_and_document_rules_match_the_artifact() {
    assert_eq!(DEFAULT_CLOCK_SKEW_MS, 300_000);
    assert_eq!(DEFAULT_MAX_SAML_RESPONSE_SIZE, 262_144);
    assert_eq!(DEFAULT_MAX_SAML_METADATA_SIZE, 102_400);
    assert_eq!(REQUIRED_DISCOVERY_FIELDS.len(), 4);
    assert_eq!(
        compute_discovery_url("https://idp.example/tenant/"),
        "https://idp.example/tenant/.well-known/openid-configuration"
    );
    assert_eq!(
        normalize_url(
            "token_endpoint",
            "oauth/token",
            "https://idp.example/tenant"
        )
        .unwrap(),
        "https://idp.example/tenant/oauth/token"
    );
    assert_eq!(
        validate_discovery_url(
            "https://idp.example/.well-known/openid-configuration",
            |_| false
        )
        .unwrap_err()
        .code,
        DiscoveryErrorCode::UntrustedOrigin
    );
    assert_eq!(
        validate_oidc_endpoint_url("tokenEndpoint", "http://127.0.0.1/token", |_| false)
            .unwrap_err()
            .code,
        DiscoveryErrorCode::PrivateHost
    );
    assert!(
        validate_oidc_endpoint_url("tokenEndpoint", "http://127.0.0.1/token", |_| true).is_ok()
    );

    let document = OidcDiscoveryDocument {
        issuer: Some("https://idp.example/tenant/".into()),
        authorization_endpoint: Some("authorize".into()),
        token_endpoint: Some("token".into()),
        jwks_uri: Some("jwks".into()),
        token_endpoint_auth_methods_supported: Some(vec!["client_secret_post".into()]),
        ..OidcDiscoveryDocument::default()
    };
    validate_discovery_document(&document, "https://idp.example/tenant").unwrap();
    let normalized = normalize_discovery_urls(&document, "https://idp.example/tenant", |url| {
        url.starts_with("https://idp.example/")
    })
    .unwrap();
    assert_eq!(
        normalized.authorization_endpoint.as_deref(),
        Some("https://idp.example/tenant/authorize")
    );
    assert_eq!(
        select_token_endpoint_auth_method(&document, None),
        SsoTokenEndpointAuthentication::ClientSecretPost
    );
    assert_eq!(
        select_token_endpoint_auth_method(
            &document,
            Some(SsoTokenEndpointAuthentication::PrivateKeyJwt)
        ),
        SsoTokenEndpointAuthentication::PrivateKeyJwt
    );
    assert!(needs_runtime_discovery(None));
    assert!(!needs_runtime_discovery(Some(&OidcConfig {
        authorization_endpoint: Some("authorization".into()),
        token_endpoint: Some("token".into()),
        jwks_endpoint: Some("jwks".into()),
        ..OidcConfig::default()
    })));
}

#[test]
fn saml_timestamp_validation_preserves_skew_and_boundary_order() {
    let now = Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).unwrap();
    let options = SamlTimestampOptions::default();
    assert_eq!(
        validate_saml_timestamp_at(
            None,
            SamlTimestampOptions {
                require_timestamps: true,
                ..options
            },
            now
        ),
        Err(SamlTimestampError::Missing)
    );
    assert!(
        validate_saml_timestamp_at(
            Some(&SamlConditions {
                not_before: Some("2026-08-30T12:05:00Z".into()),
                not_on_or_after: Some("2026-08-30T11:55:00Z".into()),
            }),
            options,
            now
        )
        .is_ok()
    );
    assert_eq!(
        validate_saml_timestamp_at(
            Some(&SamlConditions {
                not_before: None,
                not_on_or_after: Some("2026-08-30T11:54:59Z".into()),
            }),
            options,
            now
        ),
        Err(SamlTimestampError::Expired)
    );
}

#[tokio::test]
async fn discovery_fetch_rejects_redirects_and_parses_json_without_real_egress() {
    let redirect =
        local_response("HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(
        fetch_discovery_document(&redirect, 1_000, |_| true)
            .await
            .unwrap_err()
            .code,
        DiscoveryErrorCode::EndpointRedirect
    );

    let body = r#"{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token","jwks_uri":"https://idp.example/jwks"}"#;
    let success = local_response(&format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    let document = fetch_discovery_document(&success, 1_000, |_| true)
        .await
        .unwrap();
    assert_eq!(document.issuer.as_deref(), Some("https://idp.example"));
}

fn local_response(response: &str) -> String {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let response = response.to_owned();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
    });
    format!("http://{address}/.well-known/openid-configuration")
}

#[tokio::test]
async fn memory_provider_catalog_enforces_identity_and_ordering() {
    let store = MemorySsoStore::new();
    let provider = NewSsoProvider {
        id: "provider-row".into(),
        issuer: "https://sp.example".into(),
        oidc_config: Some(serde_json::json!({"clientSecret": "plaintext-upstream"})),
        saml_config: None,
        user_id: "owner".into(),
        provider_id: "workforce".into(),
        organization_id: Some("organization".into()),
        domain: "example.com".into(),
        domain_verified: Some(false),
    };
    let created = store.create(provider.clone()).await.unwrap();
    assert_eq!(created.provider_id, "workforce");
    assert_eq!(
        store
            .create(NewSsoProvider {
                id: "duplicate-row".into(),
                ..provider
            })
            .await,
        Err(SsoStoreError::DuplicateProviderId)
    );
    let updated = store
        .update(
            "provider-row",
            SsoProviderUpdate {
                domain: Some("login.example.com".into()),
                domain_verified: Some(true),
                ..SsoProviderUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.domain, "login.example.com");
    assert_eq!(updated.domain_verified, Some(true));
    assert_eq!(store.list().await.unwrap(), vec![updated.clone()]);
    assert_eq!(
        store.find_by_provider_id("workforce").await.unwrap(),
        Some(updated.clone())
    );
    assert_eq!(store.delete("provider-row").await.unwrap(), Some(updated));
    assert!(store.list().await.unwrap().is_empty());
}
