use lucid_auth::{AuthorizationRequest, BuiltinProvider, BuiltinProviderKind, SocialProvider};
use std::collections::BTreeMap;

#[test]
fn hosted_domain_hint_allows_request_override_without_duplicates() {
    let mut google = BuiltinProvider::public_client(BuiltinProviderKind::Google, "google-client");
    google.config_mut().hosted_domain = Some("configured.example".into());
    let request = |additional_params| AuthorizationRequest {
        state: "state".into(),
        code_verifier: "verifier".into(),
        id_token_nonce: None,
        redirect_uri: "http://localhost/api/auth/callback/google".into(),
        scopes: None,
        login_hint: None,
        additional_params,
    };
    let configured = google
        .create_authorization_url(&request(BTreeMap::new()))
        .unwrap();
    assert_eq!(hosted_domains(&configured), ["configured.example"]);
    let overridden = google
        .create_authorization_url(&request(BTreeMap::from([(
            "hd".into(),
            "request.example".into(),
        )])))
        .unwrap();
    assert_eq!(hosted_domains(&overridden), ["request.example"]);
}

fn hosted_domains(url: &url::Url) -> Vec<String> {
    url.query_pairs()
        .filter(|(name, _)| name == "hd")
        .map(|(_, value)| value.into_owned())
        .collect()
}
