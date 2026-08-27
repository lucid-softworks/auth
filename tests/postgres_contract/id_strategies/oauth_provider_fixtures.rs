use chrono::{Duration, Utc};
use lucid_auth::{
    OAuthProviderAccessToken, OAuthProviderClient, OAuthProviderClientAssertion,
    OAuthProviderConsent, OAuthProviderRefreshToken, OAuthProviderResource,
};

pub(super) fn resource(label: &str) -> OAuthProviderResource {
    let now = Utc::now();
    OAuthProviderResource {
        id: String::new(),
        identifier: format!("https://{label}.example/resource"),
        name: "Strategy resource".into(),
        access_token_ttl: Some(900),
        refresh_token_ttl: Some(1_800),
        signing_algorithm: None,
        signing_key_id: None,
        allowed_scopes: Some(vec!["api.read".into()]),
        custom_claims: None,
        dpop_bound_access_tokens_required: false,
        disabled: false,
        created_at: Some(now),
        updated_at: Some(now),
        policy_version: 1,
        metadata: None,
    }
}

pub(super) fn client(label: &str, user_id: &str) -> OAuthProviderClient {
    let now = Utc::now();
    OAuthProviderClient {
        id: String::new(),
        client_id: format!("strategy-{label}-client"),
        client_secret: Some("stored-secret".into()),
        client_discovery_id: None,
        disabled: false,
        skip_consent: Some(false),
        enable_end_session: Some(true),
        subject_type: Some("public".into()),
        scopes: Some(vec!["openid".into(), "offline_access".into()]),
        client_credentials_scopes: vec!["api.read".into()],
        user_id: Some(user_id.into()),
        created_at: Some(now),
        updated_at: Some(now),
        expires_at: None,
        name: Some("Strategy client".into()),
        uri: None,
        icon: None,
        contacts: None,
        tos: None,
        policy: None,
        software_id: None,
        software_version: None,
        software_statement: None,
        redirect_uris: vec!["https://client.example/callback".into()],
        post_logout_redirect_uris: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        token_endpoint_auth_method: Some("client_secret_basic".into()),
        application_type: Some("web".into()),
        jwks: None,
        jwks_uri: None,
        grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        response_types: Some(vec!["code".into()]),
        require_pkce: Some(true),
        dpop_bound_access_tokens: false,
        reference_id: None,
        metadata: None,
    }
}

pub(super) fn consent(label: &str, client_id: &str, user_id: &str) -> OAuthProviderConsent {
    let now = Utc::now();
    OAuthProviderConsent {
        id: String::new(),
        client_id: client_id.into(),
        user_id: Some(user_id.into()),
        reference_id: None,
        resources: None,
        requested_user_info_claims: None,
        scopes: vec![format!("strategy.{label}")],
        created_at: now,
        updated_at: now,
    }
}

pub(super) fn refresh_token(
    label: &str,
    client_id: &str,
    user_id: &str,
    session_id: &str,
) -> OAuthProviderRefreshToken {
    let now = Utc::now();
    OAuthProviderRefreshToken {
        id: String::new(),
        token: format!("strategy-{label}-refresh"),
        client_id: client_id.into(),
        session_id: Some(session_id.into()),
        user_id: user_id.into(),
        reference_id: None,
        authorization_code_id: None,
        resources: None,
        requested_user_info_claims: None,
        expires_at: now + Duration::hours(1),
        created_at: now,
        revoked: None,
        rotated_at: None,
        rotation_replay_response: None,
        rotation_replay_expires_at: None,
        auth_time: Some(now),
        confirmation: None,
        scopes: vec!["openid".into()],
    }
}

pub(super) fn access_token(
    label: &str,
    client_id: &str,
    user_id: &str,
    session_id: &str,
) -> OAuthProviderAccessToken {
    let now = Utc::now();
    OAuthProviderAccessToken {
        id: String::new(),
        token: format!("strategy-{label}-access"),
        client_id: client_id.into(),
        session_id: Some(session_id.into()),
        user_id: Some(user_id.into()),
        reference_id: None,
        authorization_code_id: None,
        resources: None,
        requested_user_info_claims: None,
        refresh_id: Some(String::new()),
        expires_at: now + Duration::minutes(5),
        created_at: now,
        revoked: None,
        confirmation: None,
        scopes: vec!["openid".into()],
    }
}

pub(super) fn assertion(label: &str) -> OAuthProviderClientAssertion {
    OAuthProviderClientAssertion {
        id: String::new(),
        jti: format!("strategy-{label}-assertion"),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}
