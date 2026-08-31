use super::{
    CompromisedPasswordResult, SecurityAction, SecurityEventAction, SecurityEventType,
    SentinelSecurityClient, events::SecuritySignal,
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

impl SentinelSecurityClient {
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
        let result = self
            .post(
                "/security/track-failed-login",
                json!({
                    "identifier": identifier,
                    "visitorId": visitor_id,
                    "passwordHash": password_fingerprint(self.connection.api_key(), password),
                    "ip": ip,
                    "requestId": request_id,
                    "config": self.security,
                }),
            )
            .await;
        let blocked = response_flag(result.as_ref(), "blocked");
        let challenged = response_flag(result.as_ref(), "challenged");
        if blocked || challenged {
            let details = result
                .as_ref()
                .and_then(|value| value.get("details").cloned())
                .or_else(|| result.as_ref().map(|value| json!({ "reason": value.get("reason") })))
                .unwrap_or(Value::Null);
            self.track_security_signal(SecuritySignal {
                event_type: SecurityEventType::CredentialStuffing,
                user_id: None,
                visitor_id: Some(visitor_id),
                ip,
                country: None,
                action: if blocked {
                    SecurityEventAction::Blocked
                } else {
                    SecurityEventAction::Challenged
                },
                details,
            })
            .await;
        }
        blocked
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
        if compromised {
            self.track_compromised_password(action, breach_count).await;
        }
        CompromisedPasswordResult {
            compromised,
            breach_count: (breach_count > 0).then_some(breach_count),
            action: compromised.then_some(action),
        }
    }

    async fn track_compromised_password(&self, action: SecurityAction, breach_count: u64) {
        self.track_security_signal(SecuritySignal {
            event_type: SecurityEventType::CompromisedPassword,
            user_id: None,
            visitor_id: None,
            ip: None,
            country: None,
            action: match action {
                SecurityAction::Block => SecurityEventAction::Blocked,
                SecurityAction::Challenge => SecurityEventAction::Challenged,
                SecurityAction::Log => SecurityEventAction::Logged,
            },
            details: json!({ "breachCount": breach_count }),
        })
        .await;
    }
}

fn response_flag(value: Option<&Value>, field: &str) -> bool {
    value
        .and_then(|value| value.get(field))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) fn password_fingerprint(api_key: &str, password: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(api_key.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(password.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
