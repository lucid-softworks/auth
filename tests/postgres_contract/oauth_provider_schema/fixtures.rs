use super::*;
use lucid_auth::{
    OAuthProviderAccessToken, OAuthProviderClient, OAuthProviderConsent, OAuthProviderRefreshToken,
    OAuthProviderResource,
};

pub(super) fn client(client_id: &str, user_id: &str) -> OAuthProviderClient {
    let now = now();
    OAuthProviderClient {
        id: String::new(),
        client_id: client_id.into(),
        client_secret: Some("stored-secret".into()),
        client_discovery_id: None,
        disabled: false,
        skip_consent: Some(false),
        enable_end_session: Some(true),
        subject_type: Some("public".into()),
        scopes: Some(vec!["openid".into(), "offline_access".into()]),
        client_credentials_scopes: vec!["api.read".into()],
        user_id: Some(user_id.to_owned()),
        created_at: Some(now),
        updated_at: Some(now),
        expires_at: None,
        name: Some("Storage contract client".into()),
        uri: Some("https://client.example".into()),
        icon: None,
        contacts: Some(vec!["owner@example.com".into()]),
        tos: None,
        policy: None,
        software_id: Some("storage-contract".into()),
        software_version: Some("1".into()),
        software_statement: None,
        redirect_uris: vec!["https://client.example/callback".into()],
        post_logout_redirect_uris: Some(vec!["https://client.example/logout".into()]),
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
        metadata: Some(serde_json::json!({"contract": true})),
    }
}

pub(super) fn resource(identifier: &str) -> OAuthProviderResource {
    let now = now();
    OAuthProviderResource {
        id: String::new(),
        identifier: identifier.into(),
        name: "Storage API".into(),
        access_token_ttl: Some(900),
        refresh_token_ttl: Some(1_800),
        signing_algorithm: Some("EdDSA".into()),
        signing_key_id: None,
        allowed_scopes: Some(vec!["api.read".into()]),
        custom_claims: Some(serde_json::json!({"tenant": "contract"})),
        dpop_bound_access_tokens_required: true,
        disabled: false,
        created_at: Some(now),
        updated_at: Some(now),
        policy_version: 1,
        metadata: Some(serde_json::json!({"contract": true})),
    }
}

pub(super) fn refresh(token: &str, client_id: &str, user_id: &str) -> OAuthProviderRefreshToken {
    let now = now();
    OAuthProviderRefreshToken {
        id: String::new(),
        token: token.into(),
        client_id: client_id.into(),
        session_id: None,
        user_id: user_id.to_owned(),
        reference_id: None,
        authorization_code_id: Some("authorization-code-id".into()),
        resources: Some(vec!["https://api.example".into()]),
        requested_user_info_claims: Some(vec!["email".into()]),
        expires_at: now + Duration::days(30),
        created_at: now,
        revoked: None,
        rotated_at: None,
        rotation_replay_response: None,
        rotation_replay_expires_at: None,
        auth_time: Some(now),
        confirmation: Some(serde_json::json!({"jkt": "thumbprint"})),
        scopes: vec!["openid".into(), "offline_access".into()],
    }
}

pub(super) fn access(
    token: &str,
    client_id: &str,
    user_id: &str,
    refresh_id: &str,
) -> OAuthProviderAccessToken {
    let now = now();
    OAuthProviderAccessToken {
        id: String::new(),
        token: token.into(),
        client_id: client_id.into(),
        session_id: None,
        user_id: Some(user_id.to_owned()),
        reference_id: None,
        authorization_code_id: Some("authorization-code-id".into()),
        resources: Some(vec!["https://api.example".into()]),
        requested_user_info_claims: Some(vec!["email".into()]),
        refresh_id: Some(refresh_id.to_owned()),
        expires_at: now + Duration::hours(1),
        created_at: now,
        revoked: None,
        confirmation: Some(serde_json::json!({"jkt": "thumbprint"})),
        scopes: vec!["openid".into()],
    }
}

pub(super) fn consent(client_id: &str, user_id: &str) -> OAuthProviderConsent {
    let now = now();
    OAuthProviderConsent {
        id: String::new(),
        client_id: client_id.into(),
        user_id: Some(user_id.to_owned()),
        reference_id: None,
        resources: Some(vec!["https://api.example".into()]),
        requested_user_info_claims: Some(vec!["email".into()]),
        scopes: vec!["openid".into()],
        created_at: now,
        updated_at: now,
    }
}
