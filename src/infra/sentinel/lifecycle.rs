use super::{SecurityAction, SentinelSecurityClient};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpossibleTravelResult {
    pub is_impossible: bool,
    #[serde(default)]
    pub action: Option<super::VerdictAction>,
    #[serde(default)]
    pub challenged: Option<bool>,
    #[serde(default)]
    pub challenge: Option<String>,
    #[serde(default)]
    pub pow_verified: Option<bool>,
    #[serde(default)]
    pub distance: Option<f64>,
    #[serde(default)]
    pub time_elapsed_hours: Option<f64>,
    #[serde(default)]
    pub speed_required: Option<f64>,
    #[serde(default)]
    pub from: Option<Value>,
    #[serde(default)]
    pub to: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeTrialReservation {
    pub reserved: bool,
    pub is_abuse: bool,
    pub account_count: u64,
    pub max_accounts: u64,
    pub action: SecurityAction,
}

impl FreeTrialReservation {
    fn allow() -> Self {
        Self {
            reserved: true,
            is_abuse: false,
            account_count: 0,
            max_accounts: 0,
            action: SecurityAction::Log,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleUserResult {
    pub is_stale: bool,
    #[serde(default)]
    pub days_since_last_active: Option<u64>,
    #[serde(default)]
    pub stale_days: Option<u64>,
    #[serde(default)]
    pub last_active_at: Option<String>,
    #[serde(default)]
    pub action: Option<SecurityAction>,
    #[serde(default)]
    pub notify_user: Option<bool>,
    #[serde(default)]
    pub notify_admin: Option<bool>,
}

impl SentinelSecurityClient {
    pub async fn check_impossible_travel(
        &self,
        user_id: &str,
        current_location: Option<&Value>,
        visitor_id: &str,
        ip: Option<&str>,
        pow_solution: Option<&str>,
        request_id: Option<&str>,
    ) -> Option<ImpossibleTravelResult> {
        if !self
            .security_options()
            .impossible_travel
            .as_ref()
            .is_some_and(|options| options.enabled)
        {
            return None;
        }
        let current_location = current_location?;
        let mut body = json!({
            "userId": user_id,
            "visitorId": visitor_id,
            "requestId": request_id,
            "location": current_location,
            "ip": ip,
            "config": self.security_options(),
        });
        if let Some(pow_solution) = pow_solution {
            body["powSolution"] = Value::String(pow_solution.to_owned());
        }
        self.post("/security/impossible-travel", body)
            .await
            .and_then(|value| serde_json::from_value(value).ok())
    }

    pub async fn store_last_location(
        &self,
        user_id: &str,
        location: Option<&Value>,
        ip: Option<&str>,
    ) {
        if !self
            .security_options()
            .impossible_travel
            .as_ref()
            .is_some_and(|options| options.enabled)
        {
            return;
        }
        let Some(location) = location else {
            return;
        };
        let _ = self
            .post(
                "/security/store-last-login",
                json!({ "userId": user_id, "location": location, "ip": ip }),
            )
            .await;
    }

    pub async fn reserve_free_trial_signup(
        &self,
        visitor_id: &str,
        reservation_id: &str,
        request_id: Option<&str>,
    ) -> FreeTrialReservation {
        if !self
            .security_options()
            .free_trial_abuse
            .as_ref()
            .is_some_and(|options| options.enabled)
        {
            return FreeTrialReservation::allow();
        }
        self.post(
            "/security/free-trial-abuse/reserve",
            json!({
                "visitorId": visitor_id,
                "reservationId": reservation_id,
                "requestId": request_id,
                "config": self.security_options(),
            }),
        )
        .await
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_else(FreeTrialReservation::allow)
    }

    pub async fn confirm_free_trial_signup(
        &self,
        visitor_id: &str,
        reservation_id: &str,
        user_id: &str,
        request_id: Option<&str>,
    ) {
        if !self
            .security_options()
            .free_trial_abuse
            .as_ref()
            .is_some_and(|options| options.enabled)
        {
            return;
        }
        let _ = self
            .post(
                "/security/free-trial-abuse/confirm",
                json!({
                    "visitorId": visitor_id,
                    "reservationId": reservation_id,
                    "userId": user_id,
                    "requestId": request_id,
                }),
            )
            .await;
    }

    pub async fn check_stale_user(
        &self,
        user_id: &str,
        last_active_at: Option<&str>,
    ) -> StaleUserResult {
        if !self
            .security_options()
            .stale_users
            .as_ref()
            .is_some_and(|options| options.enabled)
        {
            return StaleUserResult::default();
        }
        self.post(
            "/security/stale-user",
            json!({
                "userId": user_id,
                "lastActiveAt": last_active_at,
                "config": self.security_options(),
            }),
        )
        .await
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
    }

    /// Preserve the published 0.4.3 no-op quirk.
    pub const fn check_unknown_device(&self, _user_id: &str, _visitor_id: &str) -> bool {
        false
    }
}

#[cfg(all(test, feature = "axum"))]
mod tests {
    use super::*;
    use crate::infra::{
        dash::InfraConnectionOptions,
        sentinel::{FreeTrialAbuseOptions, ImpossibleTravelOptions, SecurityOptions},
    };
    use axum::{Json, Router, extract::State, routing::post};
    use std::sync::{Arc, Mutex};

    type Calls = Arc<Mutex<Vec<(String, Value)>>>;

    async fn handler(
        State(calls): State<Calls>,
        uri: axum::http::Uri,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        calls
            .lock()
            .unwrap()
            .push((uri.path().to_owned(), body));
        Json(match uri.path() {
            "/security/impossible-travel" => json!({
                "isImpossible": true,
                "action": "challenge",
                "challenge": "pow"
            }),
            "/security/free-trial-abuse/reserve" => json!({
                "reserved": false,
                "isAbuse": true,
                "accountCount": 3,
                "maxAccounts": 2,
                "action": "block"
            }),
            "/security/stale-user" => json!({
                "isStale": true,
                "daysSinceLastActive": 91,
                "action": "block"
            }),
            _ => json!({ "ok": true }),
        })
    }

    async fn fixture() -> (SentinelSecurityClient, Calls) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*path}", post(handler))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = SentinelSecurityClient::new(
            InfraConnectionOptions {
                api_url: Some(format!("http://{address}")),
                ..InfraConnectionOptions::default()
            },
            SecurityOptions {
                impossible_travel: Some(ImpossibleTravelOptions {
                    enabled: true,
                    max_speed_kmh: Some(800.0),
                    action: None,
                }),
                free_trial_abuse: Some(FreeTrialAbuseOptions {
                    enabled: true,
                    thresholds: None,
                    max_accounts_per_visitor: Some(2),
                    action: None,
                }),
                stale_users: Some(super::super::StaleUsersOptions {
                    enabled: true,
                    stale_days: Some(90),
                    action: None,
                    notify_user: None,
                    notify_admin: None,
                    admin_email: None,
                }),
                ..SecurityOptions::default()
            },
        );
        (client, calls)
    }

    #[tokio::test]
    async fn preserves_lifecycle_requests_and_results() {
        let (client, calls) = fixture().await;
        let location = json!({ "lat": 1, "lng": 2 });
        let travel = client
            .check_impossible_travel(
                "user",
                Some(&location),
                "visitor",
                Some("203.0.113.1"),
                Some("encoded"),
                Some("request"),
            )
            .await
            .unwrap();
        assert!(travel.is_impossible);
        assert_eq!(travel.action, Some(super::super::VerdictAction::Challenge));
        let reservation = client
            .reserve_free_trial_signup("visitor", "reservation", Some("request"))
            .await;
        assert!(reservation.is_abuse);
        assert_eq!(reservation.action, SecurityAction::Block);
        client
            .confirm_free_trial_signup("visitor", "reservation", "user", Some("request"))
            .await;
        client
            .store_last_location("user", Some(&location), Some("203.0.113.1"))
            .await;
        assert!(client.check_stale_user("user", None).await.is_stale);
        assert!(!client.check_unknown_device("user", "visitor"));

        let calls = calls.lock().unwrap();
        assert_eq!(calls[0].1["powSolution"], "encoded");
        assert_eq!(calls[1].1["config"]["freeTrialAbuse"]["maxAccountsPerVisitor"], 2);
        assert_eq!(calls[2].0, "/security/free-trial-abuse/confirm");
        assert_eq!(calls[3].0, "/security/store-last-login");
        assert_eq!(calls[4].1["config"]["staleUsers"]["staleDays"], 90);
    }

    #[tokio::test]
    async fn disabled_and_outage_paths_use_fixed_fallbacks() {
        let disabled = SentinelSecurityClient::new(
            InfraConnectionOptions::default(),
            SecurityOptions::default(),
        );
        assert!(disabled
            .reserve_free_trial_signup("visitor", "reservation", None)
            .await
            .reserved);
        assert!(disabled
            .check_impossible_travel("user", Some(&json!({})), "visitor", None, None, None)
            .await
            .is_none());
        assert!(!disabled.check_stale_user("user", None).await.is_stale);
    }
}
