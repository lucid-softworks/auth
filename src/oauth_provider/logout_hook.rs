use super::{OAuthProviderClient, OAuthProviderConfig, OAuthProviderStore, OAuthSessionLogoutPlan};
use crate::{
    AuthService, DatabaseRecord, JwtAdapterContext, JwtProtectedHeader, JwtSigningOverrides,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac as _};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use std::{collections::HashMap, sync::Arc, time::Duration as StdDuration};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

const BACKCHANNEL_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
const DELIVERY_TIMEOUT: StdDuration = StdDuration::from_secs(5);

#[derive(Clone, Default)]
pub(super) struct LogoutCoordinator {
    pending: Arc<Mutex<HashMap<String, PendingLogout>>>,
}

struct PendingLogout {
    token_plan: OAuthSessionLogoutPlan,
    clients: Vec<OAuthProviderClient>,
}

impl LogoutCoordinator {
    pub(super) async fn prepare(
        &self,
        _service: &AuthService,
        config: &OAuthProviderConfig,
        store: &dyn OAuthProviderStore,
        record: &DatabaseRecord,
    ) {
        let DatabaseRecord::Session(session) = record else {
            return;
        };
        let Ok(token_plan) = store.prepare_oauth_session_logout(&session.id).await else {
            tracing::warn!(session_id = %session.id, "failed to prepare OAuth session logout");
            return;
        };
        let mut clients = Vec::new();
        if !config.disable_jwt_plugin {
            for client_id in &token_plan.client_ids {
                match store.find_oauth_client(client_id).await {
                    Ok(Some(client))
                        if !client.disabled && client.backchannel_logout_uri.is_some() =>
                    {
                        clients.push(client);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%client_id, %error, "failed to resolve back-channel logout client")
                    }
                }
            }
        }
        self.pending.lock().await.insert(
            session.id.clone(),
            PendingLogout {
                token_plan,
                clients,
            },
        );
    }

    pub(super) async fn complete(
        &self,
        service: &AuthService,
        config: &OAuthProviderConfig,
        store: &dyn OAuthProviderStore,
        record: &DatabaseRecord,
    ) {
        let DatabaseRecord::Session(session) = record else {
            return;
        };
        let Some(pending) = self.pending.lock().await.remove(&session.id) else {
            return;
        };
        if let Err(error) = store
            .apply_oauth_session_logout(&pending.token_plan, Utc::now())
            .await
        {
            tracing::warn!(session_id = %session.id, %error, "failed to revoke OAuth session tokens");
        }
        let mut deliveries = Vec::new();
        for client in pending.clients {
            match logout_token(service, config, session, &client).await {
                Ok(token) => deliveries.push((client, token)),
                Err(error) => {
                    tracing::warn!(client_id = %client.client_id, %error, "failed to sign back-channel logout token")
                }
            }
        }
        deliver_all(deliveries).await;
    }
}

async fn logout_token(
    service: &AuthService,
    config: &OAuthProviderConfig,
    session: &crate::AuthSession,
    client: &OAuthProviderClient,
) -> Result<String, crate::AuthError> {
    let jwt = service.jwt().ok_or_else(|| {
        crate::AuthError::InvalidConfiguration(
            "JWT plugin is required for back-channel logout".into(),
        )
    })?;
    let issuer = jwt
        .configured_issuer()
        .map(str::to_owned)
        .or_else(|| service.oauth_base_url().ok())
        .ok_or_else(|| {
            crate::AuthError::InvalidConfiguration("OAuth issuer is not configured".into())
        })?;
    let issuer = super::issuer::normalize_issuer(&issuer);
    let now = Utc::now();
    let subject = subject_identifier(&session.user_id, client, config)?;
    let claims = Map::from_iter([
        ("iss".into(), Value::String(issuer)),
        ("aud".into(), Value::String(client.client_id.clone())),
        ("sub".into(), Value::String(subject)),
        ("sid".into(), Value::String(session.id.to_string())),
        ("iat".into(), json!(now.timestamp())),
        (
            "exp".into(),
            json!((now + Duration::seconds(120)).timestamp()),
        ),
        ("jti".into(), Value::String(Uuid::new_v4().to_string())),
        ("events".into(), json!({BACKCHANNEL_EVENT: {}})),
    ]);
    jwt.sign_jwt(
        &JwtAdapterContext {
            method: Some("POST".into()),
            path: Some("/oauth2/end-session".into()),
            ..Default::default()
        },
        claims,
        Some(JwtProtectedHeader {
            typ: Some("logout+jwt".into()),
            cty: None,
        }),
        JwtSigningOverrides::default(),
    )
    .await
}

async fn deliver_all(deliveries: Vec<(OAuthProviderClient, String)>) {
    let mut tasks = tokio::task::JoinSet::new();
    for (client, token) in deliveries {
        tasks.spawn(deliver(client, token));
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            tracing::warn!(%error, "back-channel logout task failed");
        }
    }
}

async fn deliver(client: OAuthProviderClient, token: String) {
    let Some(uri) = client.backchannel_logout_uri.as_deref() else {
        return;
    };
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("logout_token", &token)
        .finish();
    let client_http = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(client_id = %client.client_id, %error, "back-channel logout client creation failed");
            return;
        }
    };
    let result = client_http
        .post(uri)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .timeout(DELIVERY_TIMEOUT)
        .send()
        .await;
    match result {
        Ok(response) if matches!(response.status().as_u16(), 200 | 204) => {}
        Ok(response) => {
            tracing::warn!(client_id = %client.client_id, status = %response.status(), "back-channel logout endpoint rejected token")
        }
        Err(error) => {
            tracing::warn!(client_id = %client.client_id, %error, "back-channel logout delivery failed")
        }
    }
}

fn subject_identifier(
    user_id: &str,
    client: &OAuthProviderClient,
    config: &OAuthProviderConfig,
) -> Result<String, crate::AuthError> {
    if client.subject_type.as_deref() != Some("pairwise") {
        return Ok(user_id.to_owned());
    }
    let secret = config.pairwise_secret.as_deref().ok_or_else(|| {
        crate::AuthError::InvalidConfiguration("pairwise client requires pairwiseSecret".into())
    })?;
    let sector = client
        .redirect_uris
        .first()
        .and_then(|redirect| Url::parse(redirect).ok())
        .and_then(|url| {
            url.host_str().map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            })
        })
        .ok_or_else(|| {
            crate::AuthError::InvalidConfiguration(
                "pairwise client has no valid redirect URI".into(),
            )
        })?;
    let mut hmac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    hmac.update(format!("{sector}.{user_id}").as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hmac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, AuthenticationMethod, JwtPlugin, MemoryStore,
        oauth_provider::OAuthProviderClient,
    };
    use chrono::Duration;
    use std::collections::BTreeSet;

    #[tokio::test]
    async fn logout_token_has_the_exact_backchannel_claims_and_type() {
        let mut auth = AuthConfig::new([201_u8; 32]).unwrap();
        auth.set_base_url("https://op.example/api/auth").unwrap();
        auth.add_plugin(JwtPlugin::default()).unwrap();
        let service = AuthService::try_new(Arc::new(MemoryStore::default()), auth).unwrap();
        let now = Utc::now();
        let session = crate::AuthSession {
            id: Uuid::new_v4().to_string(),
            user_id: Uuid::new_v4().to_string(),
            token: "session-token".into(),
            actor_user_id: None,
            authentication_method: Some(AuthenticationMethod::Password),
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
            additional_fields: Map::new(),
        };
        let client = fixture_client("client-1");
        let token = logout_token(
            &service,
            &OAuthProviderConfig::new("/login", "/consent"),
            &session,
            &client,
        )
        .await
        .unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
        let claims = jsonwebtoken::dangerous::insecure_decode::<Value>(&token)
            .unwrap()
            .claims;
        let object = claims.as_object().unwrap();
        assert_eq!(
            object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from(["aud", "events", "exp", "iat", "iss", "jti", "sid", "sub"])
        );
        assert_eq!(object["iss"], "https://op.example/api/auth");
        assert_eq!(object["aud"], "client-1");
        assert_eq!(object["sub"], session.user_id.to_string());
        assert_eq!(object["sid"], session.id.to_string());
        assert_eq!(
            object["exp"].as_i64().unwrap() - object["iat"].as_i64().unwrap(),
            120
        );
        assert_eq!(object["events"], json!({BACKCHANNEL_EVENT: {}}));
        assert!(!object["jti"].as_str().unwrap().is_empty());
    }

    fn fixture_client(client_id: &str) -> OAuthProviderClient {
        OAuthProviderClient {
            id: Uuid::new_v4(),
            client_id: client_id.into(),
            client_secret: None,
            client_discovery_id: None,
            disabled: false,
            skip_consent: None,
            enable_end_session: Some(true),
            subject_type: None,
            scopes: None,
            client_credentials_scopes: Vec::new(),
            user_id: None,
            created_at: None,
            updated_at: None,
            expires_at: None,
            name: None,
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
            backchannel_logout_uri: Some("https://client.example/logout".into()),
            backchannel_logout_session_required: None,
            token_endpoint_auth_method: None,
            application_type: None,
            jwks: None,
            jwks_uri: None,
            grant_types: None,
            response_types: None,
            require_pkce: None,
            dpop_bound_access_tokens: false,
            reference_id: None,
            metadata: None,
        }
    }
}
