use super::{DashApiClient, DashPlugin, DashRequest};
use crate::{DatabaseHookContext, DatabaseHookRequest};
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
}

impl EventLocation {
    pub(crate) fn from_request(request: Option<&DatabaseHookRequest>) -> Self {
        let Some(request) = request else {
            return Self::default();
        };
        Self::from_headers(&request.headers)
    }

    pub(crate) fn from_headers(headers: &std::collections::BTreeMap<String, String>) -> Self {
        let header = |name: &str| headers.get(name).filter(|value| !value.is_empty()).cloned();
        let ip_address = [
            "cf-connecting-ip",
            "true-client-ip",
            "x-vercel-forwarded-for",
        ]
        .into_iter()
        .find_map(header)
        .and_then(|value| {
            value
                .split(',')
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        });
        Self {
            ip_address,
            city: header("x-vercel-ip-city"),
            country: header("x-vercel-ip-country-name"),
            country_code: header("cf-ipcountry").or_else(|| header("x-vercel-ip-country")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventObservation {
    pub event_type: &'static str,
    pub event_data: Value,
    pub event_key: String,
    pub event_display_name: String,
    #[serde(flatten)]
    pub location: EventLocation,
}

impl EventObservation {
    pub(crate) fn new(
        event_type: &'static str,
        event_key: impl Into<String>,
        event_display_name: impl Into<String>,
        event_data: Value,
        location: EventLocation,
    ) -> Self {
        let event_display_name = event_display_name.into();
        Self {
            event_type,
            event_data,
            event_key: event_key.into(),
            event_display_name: if event_display_name.is_empty() {
                event_type.to_owned()
            } else {
                event_display_name
            },
            location,
        }
    }
}

impl DashPlugin {
    pub(crate) fn track_event(
        &self,
        event: EventObservation,
        context: Option<&DatabaseHookContext>,
    ) {
        let client = DashApiClient::new(self.resolved_connection());
        let task = async move {
            let body = serde_json::to_value(event).expect("Dash event envelopes serialize");
            if let Err(error) = client
                .execute(DashRequest::post("/events/track", body))
                .await
            {
                tracing::debug!(error = %error, "[Dash] Failed to track event");
            }
        };
        if let Some(context) = context {
            context.run_in_background(task);
        } else {
            tokio::spawn(task);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;
    use tokio::sync::mpsc;

    #[test]
    fn envelope_omits_absent_location_and_preserves_published_keys() {
        let value = serde_json::to_value(EventObservation::new(
            "user_created",
            "user-1",
            "User signed up",
            json!({"userId": "user-1"}),
            EventLocation::default(),
        ))
        .unwrap();
        assert_eq!(
            value,
            json!({
                "eventType": "user_created",
                "eventData": {"userId": "user-1"},
                "eventKey": "user-1",
                "eventDisplayName": "User signed up"
            })
        );
    }

    #[test]
    fn request_location_uses_published_proxy_precedence() {
        let request = DatabaseHookRequest {
            method: "POST".into(),
            path: "/sign-in/email".into(),
            query: None,
            headers: BTreeMap::from([
                ("cf-connecting-ip".into(), "203.0.113.8, 10.0.0.2".into()),
                ("cf-ipcountry".into(), "GB".into()),
            ]),
        };
        let location = EventLocation::from_request(Some(&request));
        assert_eq!(location.ip_address.as_deref(), Some("203.0.113.8"));
        assert_eq!(location.country_code.as_deref(), Some("GB"));
    }

    #[tokio::test]
    async fn tracking_posts_once_and_ignores_http_error_envelopes() {
        use axum::{Json, Router, extract::State, http::StatusCode, routing::post};

        async fn track(
            State(sender): State<mpsc::UnboundedSender<Value>>,
            Json(body): Json<Value>,
        ) -> StatusCode {
            sender.send(body).unwrap();
            StatusCode::INTERNAL_SERVER_ERROR
        }

        let (sender, mut requests) = mpsc::unbounded_channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/events/track", post(track)).with_state(sender),
            )
            .await
            .unwrap();
        });
        let plugin = DashPlugin::new(super::super::DashOptions {
            connection: super::super::InfraConnectionOptions {
                api_url: Some(format!("http://{address}")),
                api_key: Some("managed-key".into()),
                ..super::super::InfraConnectionOptions::default()
            },
            ..super::super::DashOptions::default()
        });
        plugin.track_event(
            EventObservation::new(
                "user_created",
                "user-1",
                "User signed up",
                json!({"userId": "user-1"}),
                EventLocation::default(),
            ),
            None,
        );
        let request = tokio::time::timeout(std::time::Duration::from_secs(2), requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request["eventType"], "user_created");
        assert_eq!(request["eventKey"], "user-1");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), requests.recv())
                .await
                .is_err()
        );
        server.abort();
    }
}
