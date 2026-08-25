use crate::{AgentApprovalMethod, AgentApprovalRequest};
use serde_json::Value;

pub(super) fn deliver(requests: &[AgentApprovalRequest], payload: Value) {
    let client = reqwest::Client::new();
    for request in requests.iter().filter(|request| eligible(request)) {
        let Some(endpoint) = request.client_notification_endpoint.clone() else {
            continue;
        };
        let Some(token) = request.client_notification_token.clone() else {
            continue;
        };
        let client = client.clone();
        let payload = payload.clone();
        tokio::spawn(async move {
            let _ = client
                .post(endpoint)
                .bearer_auth(token)
                .json(&payload)
                .send()
                .await;
        });
    }
}

fn eligible(request: &AgentApprovalRequest) -> bool {
    request.method == AgentApprovalMethod::Ciba
        && request.client_notification_endpoint.is_some()
        && request.client_notification_token.is_some()
        && matches!(request.delivery_mode.as_deref(), Some("ping" | "push"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentApprovalMethod, AgentApprovalStatus};
    use chrono::{Duration, Utc};

    fn request(mode: Option<&str>) -> AgentApprovalRequest {
        let now = Utc::now();
        AgentApprovalRequest {
            id: "approval".into(),
            method: AgentApprovalMethod::Ciba,
            agent_id: Some("agent".into()),
            host_id: Some("host".into()),
            user_id: None,
            capabilities: None,
            status: AgentApprovalStatus::Pending,
            user_code_hash: None,
            login_hint: None,
            binding_message: None,
            client_notification_token: Some("secret".into()),
            client_notification_endpoint: Some("https://example.test/callback".into()),
            delivery_mode: mode.map(str::to_owned),
            interval: 5.0,
            last_polled_at: None,
            expires_at: now + Duration::minutes(5),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn only_ping_and_push_ciba_requests_are_delivered() {
        assert!(eligible(&request(Some("ping"))));
        assert!(eligible(&request(Some("push"))));
        assert!(!eligible(&request(Some("poll"))));
        let mut device = request(Some("ping"));
        device.method = AgentApprovalMethod::DeviceAuthorization;
        assert!(!eligible(&device));
    }
}
