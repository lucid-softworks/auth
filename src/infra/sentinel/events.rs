use super::SentinelSecurityClient;
use crate::infra::dash::DashRequest;
#[cfg(feature = "axum")]
use crate::infra::dash::IdentificationContext;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    UnknownDevice,
    CredentialStuffing,
    ImpossibleTravel,
    GeoBlocked,
    BotBlocked,
    SuspiciousIpDetected,
    VelocityExceeded,
    FreeTrialAbuse,
    CompromisedPassword,
    StaleAccountReactivation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityEventAction {
    Logged,
    Blocked,
    Challenged,
}

pub(super) struct SecuritySignal<'a> {
    pub event_type: SecurityEventType,
    pub user_id: Option<&'a str>,
    pub visitor_id: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub country: Option<&'a str>,
    pub action: SecurityEventAction,
    pub details: Value,
}

#[cfg(feature = "axum")]
pub(super) struct SecurityCheckObservation<'a> {
    pub identification: &'a IdentificationContext,
    pub path: &'a str,
    pub identifier: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub outcome: &'static str,
    pub checks: &'a [&'a str],
    pub triggered_by: Option<&'a str>,
    pub details: Option<Value>,
}

impl SentinelSecurityClient {
    pub(super) async fn track_impossible_travel(
        &self,
        result: &super::ImpossibleTravelResult,
        user_id: &str,
        visitor_id: &str,
        current_location: &Value,
    ) {
        if !result.is_impossible {
            return;
        }
        self.track_security_signal(SecuritySignal {
            event_type: SecurityEventType::ImpossibleTravel,
            user_id: Some(user_id),
            visitor_id: Some(visitor_id),
            ip: None,
            country: current_location
                .get("country")
                .and_then(|country| country.get("code"))
                .and_then(Value::as_str),
            action: verdict_action(result.action),
            details: json!({
                "from": result.from,
                "to": result.to,
                "distance": result.distance,
                "speedRequired": result.speed_required,
                "action": result.action,
            }),
        })
        .await;
    }

    pub(super) async fn track_free_trial_abuse(
        &self,
        result: &super::FreeTrialReservation,
        visitor_id: &str,
    ) {
        if !result.is_abuse {
            return;
        }
        self.track_security_signal(SecuritySignal {
            event_type: SecurityEventType::FreeTrialAbuse,
            user_id: None,
            visitor_id: Some(visitor_id),
            ip: None,
            country: None,
            action: security_action(result.action),
            details: json!({
                "accountCount": result.account_count,
                "maxAccounts": result.max_accounts,
            }),
        })
        .await;
    }

    pub(super) async fn track_stale_account(
        &self,
        result: &super::StaleUserResult,
        user_id: &str,
    ) {
        if !result.is_stale {
            return;
        }
        self.track_security_signal(SecuritySignal {
            event_type: SecurityEventType::StaleAccountReactivation,
            user_id: Some(user_id),
            visitor_id: None,
            ip: None,
            country: None,
            action: result
                .action
                .map_or(SecurityEventAction::Logged, security_action),
            details: json!({
                "daysSinceLastActive": result.days_since_last_active,
                "staleDays": result.stale_days,
                "lastActiveAt": result.last_active_at,
                "notifyUser": result.notify_user,
                "notifyAdmin": result.notify_admin,
            }),
        })
        .await;
    }

    pub(super) async fn track_security_signal(&self, signal: SecuritySignal<'_>) {
        let SecuritySignal {
            event_type,
            user_id,
            visitor_id,
            ip,
            country,
            action,
            details,
        } = signal;
        let event_type_value = serde_json::to_value(event_type).expect("event type serializes");
        let event_type_name = event_type_value
            .as_str()
            .unwrap_or("credential_stuffing")
            .to_owned();
        let mut event_data = Map::new();
        event_data.insert("type".into(), event_type_value);
        if let Some(user_id) = user_id {
            event_data.insert("userId".into(), Value::String(user_id.to_owned()));
        }
        if let Some(visitor_id) = visitor_id {
            event_data.insert("visitorId".into(), Value::String(visitor_id.to_owned()));
        }
        event_data.insert(
            "action".into(),
            serde_json::to_value(action).expect("event action serializes"),
        );
        if let Value::Object(details) = details {
            event_data.extend(details);
        }
        let mut body = json!({
            "eventKey": visitor_id.or(user_id).unwrap_or("unknown"),
            "eventType": "security_signal",
            "eventDisplayName": format!("Security signal: {}", event_type_name.replace('_', " ")),
            "eventData": event_data,
        });
        insert_optional(&mut body, "ipAddress", ip);
        insert_optional(&mut body, "country", country);
        self.track_event(body).await;
    }

    #[cfg(feature = "axum")]
    pub(super) async fn track_security_check(&self, check: SecurityCheckObservation<'_>) {
        let SecurityCheckObservation {
            identification,
            path,
            identifier,
            user_agent,
            outcome,
            checks,
            triggered_by,
            details,
        } = check;
        if checks.is_empty() {
            return;
        }
        let location = identification.location.as_ref();
        let reason = details
            .as_ref()
            .and_then(|details| details.get("reason"))
            .and_then(Value::as_str)
            .or(triggered_by);
        let mut checks = checks.to_vec();
        checks.sort_unstable();
        let mut event_data = json!({
            "outcome": outcome,
            "evaluatedChecks": checks,
            "path": path,
        });
        insert_optional(&mut event_data, "triggeredBy", triggered_by);
        insert_optional(&mut event_data, "reason", reason);
        insert_optional(&mut event_data, "identifier", identifier);
        insert_optional(&mut event_data, "userAgent", user_agent);
        if let Some(details) = details {
            event_data["details"] = details;
        }
        let mut body = json!({
            "eventKey": identification.visitor_id.as_deref()
                .or(identification.ip.as_deref())
                .or(identification.untrusted_visitor_id.as_deref())
                .unwrap_or("unknown"),
            "eventType": "security_check",
            "eventDisplayName": format!("Security: {outcome}"),
            "eventData": event_data,
        });
        insert_optional(
            &mut body,
            "ipAddress",
            location
                .and_then(|location| location.ip_address.as_deref())
                .or(identification.ip.as_deref()),
        );
        insert_optional(
            &mut body,
            "city",
            location.and_then(|location| location.city.as_deref()),
        );
        insert_optional(
            &mut body,
            "country",
            location.and_then(|location| location.country.as_deref()),
        );
        insert_optional(
            &mut body,
            "countryCode",
            location.and_then(|location| location.country_code.as_deref()),
        );
        self.track_event(body).await;
    }

    async fn track_event(&self, body: Value) {
        if let Err(error) = self
            .api
            .execute(DashRequest::post("/events/track", body))
            .await
        {
            tracing::debug!(error = %error, "[Dash] Failed to track event");
        }
    }
}

fn insert_optional(value: &mut Value, field: &str, item: Option<&str>) {
    if let (Value::Object(object), Some(item)) = (value, item) {
        object.insert(field.to_owned(), Value::String(item.to_owned()));
    }
}

pub(super) fn verdict_event_type(reason: Option<&str>) -> SecurityEventType {
    match reason {
        Some("geo_blocked") => SecurityEventType::GeoBlocked,
        Some("bot_detected") => SecurityEventType::BotBlocked,
        Some("suspicious_ip_detected") => SecurityEventType::SuspiciousIpDetected,
        Some("rate_limited") => SecurityEventType::VelocityExceeded,
        _ => SecurityEventType::CredentialStuffing,
    }
}

fn security_action(action: super::SecurityAction) -> SecurityEventAction {
    match action {
        super::SecurityAction::Log => SecurityEventAction::Logged,
        super::SecurityAction::Block => SecurityEventAction::Blocked,
        super::SecurityAction::Challenge => SecurityEventAction::Challenged,
    }
}

fn verdict_action(action: Option<super::VerdictAction>) -> SecurityEventAction {
    match action {
        Some(super::VerdictAction::Block) => SecurityEventAction::Blocked,
        Some(super::VerdictAction::Challenge) => SecurityEventAction::Challenged,
        _ => SecurityEventAction::Logged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "axum")]
    use crate::infra::{dash::InfraConnectionOptions, sentinel::SecurityOptions};
    #[cfg(feature = "axum")]
    use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
    #[cfg(feature = "axum")]
    use tokio::sync::mpsc;

    #[test]
    fn declares_all_ten_published_signal_types() {
        let types = [
            SecurityEventType::UnknownDevice,
            SecurityEventType::CredentialStuffing,
            SecurityEventType::ImpossibleTravel,
            SecurityEventType::GeoBlocked,
            SecurityEventType::BotBlocked,
            SecurityEventType::SuspiciousIpDetected,
            SecurityEventType::VelocityExceeded,
            SecurityEventType::FreeTrialAbuse,
            SecurityEventType::CompromisedPassword,
            SecurityEventType::StaleAccountReactivation,
        ];
        assert_eq!(types.len(), 10);
        assert_eq!(verdict_event_type(Some("bot_detected")), SecurityEventType::BotBlocked);
        assert_eq!(verdict_event_type(Some("unknown")), SecurityEventType::CredentialStuffing);
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn posts_exact_signal_envelope_without_null_optionals() {
        async fn track(
            State(sender): State<mpsc::UnboundedSender<Value>>,
            Json(body): Json<Value>,
        ) -> StatusCode {
            sender.send(body).unwrap();
            StatusCode::OK
        }
        let (sender, mut requests) = mpsc::unbounded_channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/events/track", post(track)).with_state(sender),
            )
            .await
            .unwrap()
        });
        let client = SentinelSecurityClient::new(
            InfraConnectionOptions {
                api_url: Some(format!("http://{address}")),
                api_key: Some("key".into()),
                ..InfraConnectionOptions::default()
            },
            SecurityOptions::default(),
        );
        client
            .track_security_signal(SecuritySignal {
                event_type: SecurityEventType::BotBlocked,
                user_id: None,
                visitor_id: Some("visitor"),
                ip: None,
                country: None,
                action: SecurityEventAction::Blocked,
                details: json!({ "reason": "bot_detected" }),
            })
            .await;
        assert_eq!(
            requests.recv().await.unwrap(),
            json!({
                "eventKey": "visitor",
                "eventType": "security_signal",
                "eventDisplayName": "Security signal: bot blocked",
                "eventData": {
                    "type": "bot_blocked",
                    "visitorId": "visitor",
                    "action": "blocked",
                    "reason": "bot_detected"
                }
            })
        );
    }
}
