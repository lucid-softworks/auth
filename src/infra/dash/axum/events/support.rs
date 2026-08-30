use crate::{DashEvent, DashPlugin};
use axum::{
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EventQuery {
    pub limit: Option<f64>,
    pub offset: Option<f64>,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub identifier: Option<String>,
    pub event_type: Option<String>,
}

pub(super) fn configured(plugin: &DashPlugin) -> bool {
    !plugin.resolved_connection().api_key().is_empty()
}

pub(super) fn events_not_configured() -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Events API is not configured",
    )
}

pub(super) fn elevated_forbidden() -> Response {
    error(
        StatusCode::FORBIDDEN,
        "FORBIDDEN",
        "Only organization owners and admins can view activity logs.",
    )
}

pub(super) fn remote_error(message: &'static str) -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        message,
    )
}

pub(super) fn error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response {
    crate::axum::api_error(status, code, message)
}

pub(super) async fn fetch(
    plugin: &DashPlugin,
    path: &str,
    query: &[(&str, &str)],
) -> Result<crate::DashClientResponse, crate::DashClientError> {
    let query = serde_urlencoded::to_string(query).unwrap_or_default();
    let path = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    crate::DashApiClient::new(plugin.resolved_connection())
        .execute(crate::DashRequest::get(path))
        .await
}

pub(super) fn page_or_log(
    response: Result<crate::DashClientResponse, crate::DashClientError>,
    operation: &'static str,
) -> Option<RemotePage> {
    match response {
        Ok(response) if response.error.is_none() => response.data.and_then(RemotePage::parse),
        Ok(response) => {
            tracing::error!(operation, error = ?response.error, "[Dash] remote event query failed");
            None
        }
        Err(error) => {
            tracing::error!(operation, error = %error, "[Dash] remote event query failed");
            None
        }
    }
}

#[derive(Debug)]
pub(super) struct RemotePage {
    events: Vec<Value>,
    total: Value,
    limit: Value,
    offset: Value,
}

impl RemotePage {
    fn parse(value: Value) -> Option<Self> {
        let value = value.as_object()?;
        Some(Self {
            events: value.get("events")?.as_array()?.clone(),
            total: value.get("total")?.clone(),
            limit: value.get("limit")?.clone(),
            offset: value.get("offset")?.clone(),
        })
    }

    pub(super) fn response(
        self,
        event_type: Option<&str>,
        organization: Option<OrganizationFilter<'_>>,
        filtered_total: bool,
    ) -> Value {
        let events = self
            .events
            .into_iter()
            .filter(|event| organization.is_none_or(|filter| filter.matches(event)))
            .map(|event| DashEvent::from_remote(&event))
            .filter(|event| event_type.is_none_or(|kind| event.event_type_str() == Some(kind)))
            .collect::<Vec<_>>();
        let total = if filtered_total {
            Value::from(events.len())
        } else {
            self.total
        };
        json!({
            "events": events,
            "total": total,
            "limit": self.limit,
            "offset": self.offset,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct OrganizationFilter<'a> {
    pub user_id: &'a str,
    pub identifier: Option<&'a str>,
}

impl OrganizationFilter<'_> {
    fn matches(self, event: &Value) -> bool {
        let event_data = event.get("eventData").and_then(Value::as_object);
        let event_user_id = event_data
            .and_then(|data| data.get("userId"))
            .and_then(Value::as_str);
        let event_identifier = event_data
            .and_then(|data| data.get("identifier"))
            .and_then(Value::as_str);
        let matches_user = event_user_id == Some(self.user_id)
            || event.get("eventKey").and_then(Value::as_str) == Some(self.user_id);
        let matches_identifier = self
            .identifier
            .is_none_or(|identifier| event_identifier == Some(identifier));
        matches_user && matches_identifier
    }
}

pub(super) struct Paging {
    pub limit: String,
    pub offset: String,
}

impl Paging {
    pub(super) fn new(limit: Option<f64>, offset: Option<f64>) -> Self {
        Self {
            limit: js_number_string(js_clamp(limit.unwrap_or(50.0), 1.0, 100.0)),
            offset: js_number_string(js_max(offset.unwrap_or(0.0), 0.0)),
        }
    }
}

fn js_clamp(value: f64, minimum: f64, maximum: f64) -> f64 {
    if value.is_nan() {
        value
    } else {
        value.max(minimum).min(maximum)
    }
}

fn js_max(value: f64, minimum: f64) -> f64 {
    if value.is_nan() {
        value
    } else {
        value.max(minimum)
    }
}

fn js_number_string(value: f64) -> String {
    ryu_js::Buffer::new().format(value).to_owned()
}

pub(super) fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(super) fn truthy(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging_matches_javascript_clamping_and_nan_behavior() {
        let default = Paging::new(None, None);
        assert_eq!((default.limit.as_str(), default.offset.as_str()), ("50", "0"));
        let clamped = Paging::new(Some(500.0), Some(-4.0));
        assert_eq!((clamped.limit.as_str(), clamped.offset.as_str()), ("100", "0"));
        let nan = Paging::new(Some(f64::NAN), Some(f64::NAN));
        assert_eq!((nan.limit.as_str(), nan.offset.as_str()), ("NaN", "NaN"));
    }

    #[test]
    fn organization_filter_matches_user_key_identifier_and_event_type() {
        let page = RemotePage {
            events: vec![
                json!({"eventType": "one", "eventKey": "user-1", "eventData": {"identifier": "id-1"}}),
                json!({"eventType": "two", "eventKey": "other", "eventData": {"userId": "user-1", "identifier": "id-1"}}),
                json!({"eventType": "two", "eventKey": "other", "eventData": {"userId": "user-2", "identifier": "id-1"}}),
            ],
            total: json!(80),
            limit: json!(50),
            offset: json!(0),
        };
        let value = page.response(
            Some("two"),
            Some(OrganizationFilter {
                user_id: "user-1",
                identifier: Some("id-1"),
            }),
            true,
        );
        assert_eq!(value["events"].as_array().unwrap().len(), 1);
        assert_eq!(value["total"], 1);
    }
}
