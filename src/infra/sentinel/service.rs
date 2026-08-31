use super::{SecurityAction, SecurityOptions};
use crate::infra::dash::{
    DashApiClient, DashRequest, InfraConnectionOptions, ResolvedConnectionOptions,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictAction {
    Allow,
    Challenge,
    Block,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityVerdict {
    pub action: VerdictAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pow_verified: Option<bool>,
}

impl SecurityVerdict {
    fn allow() -> Self {
        Self {
            action: VerdictAction::Allow,
            challenge: None,
            reason: None,
            details: None,
            pow_verified: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCheck {
    pub visitor_id: Option<String>,
    pub request_id: Option<String>,
    pub ip: Option<String>,
    pub path: String,
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow_solution: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompromisedPasswordResult {
    pub compromised: bool,
    pub breach_count: Option<u64>,
    pub action: Option<SecurityAction>,
}

#[derive(Clone, Debug)]
pub struct SentinelSecurityClient {
    api: DashApiClient,
    connection: ResolvedConnectionOptions,
    security: SecurityOptions,
}

impl SentinelSecurityClient {
    pub fn new(connection: InfraConnectionOptions, security: SecurityOptions) -> Self {
        let connection = connection.resolve();
        Self::from_resolved(connection, security)
    }

    pub(crate) fn from_resolved(
        connection: ResolvedConnectionOptions,
        security: SecurityOptions,
    ) -> Self {
        Self {
            api: DashApiClient::new(&connection),
            connection,
            security,
        }
    }

    pub(super) fn security_options(&self) -> &SecurityOptions {
        &self.security
    }

    pub async fn check_security(&self, check: SecurityCheck) -> SecurityVerdict {
        self.post(
            "/security/check",
            json!({
                "visitorId": check.visitor_id,
                "requestId": check.request_id,
                "ip": check.ip,
                "path": check.path,
                "identifier": check.identifier,
                "powSolution": check.pow_solution,
                "config": self.security,
            }),
        )
        .await
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_else(SecurityVerdict::allow)
    }

    pub async fn is_blocked(
        &self,
        visitor_id: &str,
        ip: Option<&str>,
        request_id: Option<&str>,
    ) -> bool {
        let query = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("visitorId", visitor_id);
            if let Some(ip) = ip {
                serializer.append_pair("ip", ip);
            }
            if let Some(request_id) = request_id {
                serializer.append_pair("requestId", request_id);
            }
            serializer.finish()
        };
        self.get(&format!("/security/is-blocked?{query}"))
            .await
        .and_then(|value| value.get("blocked").and_then(Value::as_bool))
        .unwrap_or(false)
    }

    pub async fn generate_challenge(
        &self,
        visitor_id: &str,
        request_id: Option<&str>,
    ) -> String {
        self.post(
            "/security/pow/generate",
            json!({
                "visitorId": visitor_id,
                "requestId": request_id,
                "difficulty": self.security.challenge_difficulty,
            }),
        )
        .await
        .and_then(|value| {
            value
                .get("challenge")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
    }

    pub async fn track_failed_attempt(
        &self,
        identifier: &str,
        visitor_id: &str,
        password: &str,
        ip: Option<&str>,
        request_id: Option<&str>,
    ) -> bool {
        if self.connection.api_key().is_empty() {
            tracing::warn!(
                "[Sentinel] Missing apiKey; failed-login password fingerprint is skipped."
            );
            return false;
        }
        let password_hash = password_fingerprint(self.connection.api_key(), password);
        self.post(
            "/security/track-failed-login",
            json!({
                "identifier": identifier,
                "visitorId": visitor_id,
                "passwordHash": password_hash,
                "ip": ip,
                "requestId": request_id,
                "config": self.security,
            }),
        )
        .await
        .and_then(|value| value.get("blocked").and_then(Value::as_bool))
        .unwrap_or(false)
    }

    pub async fn clear_failed_attempts(&self, identifier: &str) {
        let _ = self
            .post(
                "/security/clear-failed-attempts",
                json!({ "identifier": identifier }),
            )
            .await;
    }

    pub async fn check_compromised_password(
        &self,
        password: &str,
    ) -> CompromisedPasswordResult {
        let hash = hex::encode_upper(Sha1::digest(password.as_bytes()));
        let (prefix, suffix) = hash.split_at(5);
        let Some(value) = self
            .post(
                "/security/breached-passwords",
                json!({ "passwordPrefix": prefix, "config": self.security }),
            )
            .await
        else {
            return CompromisedPasswordResult::default();
        };
        if !value.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
            return CompromisedPasswordResult::default();
        }
        let breach_count = value
            .get("suffixes")
            .and_then(|suffixes| suffixes.get(suffix))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let minimum = value
            .get("minBreachCount")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        let action = value
            .get("action")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or(SecurityAction::Block);
        let compromised = breach_count >= minimum;
        CompromisedPasswordResult {
            compromised,
            breach_count: (breach_count > 0).then_some(breach_count),
            action: compromised.then_some(action),
        }
    }

    async fn get(&self, path: &str) -> Option<Value> {
        self.api
            .execute(DashRequest::get(path))
            .await
            .ok()
            .and_then(|response| response.data)
    }

    pub(super) async fn post(&self, path: &str, body: Value) -> Option<Value> {
        self.api
            .execute(DashRequest::post(path, body))
            .await
            .ok()
            .and_then(|response| response.data)
    }
}

fn password_fingerprint(api_key: &str, password: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(api_key.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(password.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(all(test, feature = "axum"))]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, Uri},
        response::IntoResponse,
        routing::{get, post},
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    struct Call {
        uri: Uri,
        headers: HeaderMap,
        body: Value,
    }

    async fn get_handler(
        State(calls): State<Arc<Mutex<Vec<Call>>>>,
        uri: Uri,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        calls.lock().unwrap().push(Call {
            uri,
            headers,
            body: Value::Null,
        });
        Json(json!({ "blocked": true }))
    }

    async fn post_handler(
        State(calls): State<Arc<Mutex<Vec<Call>>>>,
        uri: Uri,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        calls.lock().unwrap().push(Call {
            uri: uri.clone(),
            headers,
            body: body.clone(),
        });
        match uri.path() {
            "/security/check" => Json(json!({
                "action": "challenge",
                "reason": "bot_detected"
            })),
            "/security/pow/generate" => Json(json!({ "challenge": "encoded" })),
            "/security/track-failed-login" => Json(json!({ "blocked": true })),
            "/security/breached-passwords" => {
                let suffix = hex::encode_upper(Sha1::digest(b"password"));
                Json(json!({
                    "enabled": true,
                    "suffixes": { &suffix[5..]: 12 },
                    "minBreachCount": 10,
                    "action": "challenge"
                }))
            }
            _ => Json(json!({ "ok": true })),
        }
    }

    async fn fixture() -> (SentinelSecurityClient, Arc<Mutex<Vec<Call>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/security/is-blocked", get(get_handler))
            .route("/{*path}", post(post_handler))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = SentinelSecurityClient::new(
            InfraConnectionOptions {
                api_url: Some(format!("http://{address}")),
                api_key: Some("sentinel-key".into()),
                ..InfraConnectionOptions::default()
            },
            SecurityOptions {
                challenge_difficulty: Some(20),
                ..SecurityOptions::default()
            },
        );
        (client, calls)
    }

    #[tokio::test]
    async fn sends_the_exact_core_security_requests() {
        let (client, calls) = fixture().await;
        let verdict = client
            .check_security(SecurityCheck {
                visitor_id: Some("visitor".into()),
                request_id: Some("request".into()),
                path: "/sign-in/email".into(),
                identifier: Some("user@example.com".into()),
                ..SecurityCheck::default()
            })
            .await;
        assert_eq!(verdict.action, VerdictAction::Challenge);
        assert!(client.is_blocked("visitor", Some("203.0.113.1"), Some("request")).await);
        assert_eq!(client.generate_challenge("visitor", Some("request")).await, "encoded");
        assert!(client
            .track_failed_attempt(
                "user@example.com",
                "visitor",
                "secret",
                None,
                Some("request")
            )
            .await);

        let calls = calls.lock().unwrap();
        assert_eq!(calls[0].body["config"]["challengeDifficulty"], 20);
        assert_eq!(
            calls[1].uri.query(),
            Some("visitorId=visitor&ip=203.0.113.1&requestId=request")
        );
        assert_eq!(
            calls[3].body["passwordHash"],
            password_fingerprint("sentinel-key", "secret")
        );
        assert_eq!(calls[3].headers["x-api-key"], "sentinel-key");
    }

    #[tokio::test]
    async fn sends_only_a_sha1_prefix_for_breached_passwords() {
        let (client, calls) = fixture().await;
        let result = client.check_compromised_password("password").await;
        assert_eq!(
            result,
            CompromisedPasswordResult {
                compromised: true,
                breach_count: Some(12),
                action: Some(SecurityAction::Challenge),
            }
        );
        let call = calls.lock().unwrap().pop().unwrap();
        assert_eq!(call.body["passwordPrefix"], "5BAA6");
        assert!(call.body.get("password").is_none());
    }

    #[tokio::test]
    async fn preserves_fixed_fail_open_fallbacks() {
        let client = SentinelSecurityClient::new(
            InfraConnectionOptions {
                api_url: Some("http://127.0.0.1:1".into()),
                api_key: Some("key".into()),
                ..InfraConnectionOptions::default()
            },
            SecurityOptions::default(),
        );
        assert_eq!(
            client.check_security(SecurityCheck::default()).await.action,
            VerdictAction::Allow
        );
        assert!(!client.is_blocked("visitor", None, None).await);
        assert!(client.generate_challenge("visitor", None).await.is_empty());
        assert!(!client
            .check_compromised_password("secret")
            .await
            .compromised);
    }
}
