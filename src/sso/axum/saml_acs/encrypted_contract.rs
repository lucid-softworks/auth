use super::*;
use crate::{AuthConfig, MemoryStore, SsoProvider};
use samlet::raw::{
    Binding, EntitySetting, IdentityProvider, LoginResponseOptions, ServiceProvider, User,
    metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig},
};
use serde_json::{Map, json};
use std::sync::Arc;

const PRIVATE_KEY: &str = include_str!("../../../../tests/fixtures/saml_private_key.pem");
const CERTIFICATE: &str = include_str!("../../../../tests/fixtures/saml_signing_cert.pem");

#[test]
fn encrypted_signed_assertion_uses_the_configured_sp_decryption_key() {
    let mut auth = AuthConfig::new([83; 32]).unwrap();
    auth.set_base_url("https://example.com").unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), auth);
    let options = crate::SsoOptions {
        saml_algorithms: crate::SamlAlgorithmOptions {
            allowed_signature_algorithms: Some(vec![crate::SignatureAlgorithm::RSA_SHA256.into()]),
            ..crate::SamlAlgorithmOptions::default()
        },
        ..crate::SsoOptions::default()
    };
    let provider = provider();
    let config = provider.saml_config.as_ref().unwrap().as_object().unwrap();
    let entities = config::entities(&service, &provider, config, &options).unwrap();
    let response = encrypted_response();

    let session = parse_session(
        entities,
        "relay-state",
        "_encrypted-request",
        response,
        &options,
    )
    .unwrap();
    assert_eq!(session.name_id().value(), "encrypted-user@example.com");
}

fn provider() -> SsoProvider {
    SsoProvider {
        id: "encrypted-provider-row".into(),
        issuer: "https://sp.example.com/metadata".into(),
        oidc_config: None,
        saml_config: Some(json!({
            "issuer": "https://sp.example.com/metadata",
            "entryPoint": "https://idp.example.com/sso",
            "cert": CERTIFICATE,
            "idpMetadata": {"entityID": "https://idp.example.com/metadata"},
            "wantAssertionsSigned": true,
            "spMetadata": {
                "isAssertionEncrypted": true,
                "encPrivateKey": PRIVATE_KEY
            }
        })),
        user_id: "owner".into(),
        provider_id: "encrypted-saml".into(),
        organization_id: None,
        domain: "example.com".into(),
        domain_verified: None,
        additional_fields: Map::new(),
    }
}

fn encrypted_response() -> String {
    let acs = "https://example.com/api/auth/sso/saml2/sp/acs/encrypted-saml";
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            want_assertions_signed: true,
            signing_certs: vec![CERTIFICATE.into()],
            encrypt_certs: vec![CERTIFICATE.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, acs)],
            ..Default::default()
        },
        EntitySetting::default(),
    )
    .unwrap();
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVATE_KEY.into());
    setting.signing_cert = Some(CERTIFICATE.into());
    setting.is_assertion_encrypted = true;
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERTIFICATE.into()],
            single_sign_on_service: vec![Endpoint::new(
                Binding::Redirect,
                "https://idp.example.com/sso",
            )],
            ..Default::default()
        },
        setting,
    )
    .unwrap();
    idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("encrypted-user@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_encrypted-request"),
            relay_state: Some("relay-state"),
            ..Default::default()
        },
    )
    .unwrap()
    .context
}
