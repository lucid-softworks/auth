use async_trait::async_trait;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AgentAuthEvent {
    Audit(Box<AgentAuthAuditEvent>),
    CapabilityExecuted(Box<AgentAuthCapabilityExecutionEvent>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentAuthAuditEvent {
    pub r#type: AgentAuthAuditEventType,
    #[serde(flatten)]
    pub fields: AgentAuthEventFields,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentAuthCapabilityExecutionEvent {
    #[serde(rename = "type")]
    pub event_type: AgentCapabilityExecutedEventType,
    pub capability: String,
    pub status: AgentCapabilityExecutionStatus,
    #[serde(flatten)]
    pub fields: AgentAuthExecutionEventFields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AgentCapabilityExecutedEventType {
    #[serde(rename = "capability.executed")]
    CapabilityExecuted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentCapabilityExecutionStatus {
    Success,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAuthEventFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAuthExecutionEventFields {
    #[serde(flatten)]
    pub base: AgentAuthEventFields,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AgentAuthAuditEventType {
    #[serde(rename = "agent.created")]
    AgentCreated,
    #[serde(rename = "agent.updated")]
    AgentUpdated,
    #[serde(rename = "agent.revoked")]
    AgentRevoked,
    #[serde(rename = "agent.claimed")]
    AgentClaimed,
    #[serde(rename = "agent.reactivated")]
    AgentReactivated,
    #[serde(rename = "agent.key_rotated")]
    AgentKeyRotated,
    #[serde(rename = "agent.cleanup")]
    AgentCleanup,
    #[serde(rename = "host.created")]
    HostCreated,
    #[serde(rename = "host.enrolled")]
    HostEnrolled,
    #[serde(rename = "host.updated")]
    HostUpdated,
    #[serde(rename = "host.revoked")]
    HostRevoked,
    #[serde(rename = "host.reactivated")]
    HostReactivated,
    #[serde(rename = "host.key_rotated")]
    HostKeyRotated,
    #[serde(rename = "host.claimed")]
    HostClaimed,
    #[serde(rename = "capability.requested")]
    CapabilityRequested,
    #[serde(rename = "capability.approved")]
    CapabilityApproved,
    #[serde(rename = "capability.denied")]
    CapabilityDenied,
    #[serde(rename = "capability.granted")]
    CapabilityGranted,
    #[serde(rename = "capability.revoked")]
    CapabilityRevoked,
    #[serde(rename = "approval.created")]
    ApprovalCreated,
    #[serde(rename = "approval.approved")]
    ApprovalApproved,
    #[serde(rename = "approval.denied")]
    ApprovalDenied,
}

#[async_trait]
pub trait AgentEventCallback: Send + Sync {
    /// Delivers an Agent Auth audit or execution event.
    ///
    /// Returning an error records a delivery failure without failing the
    /// request which produced the event, matching Better Auth's fail-open
    /// `onEvent` callback contract.
    async fn call(&self, event: AgentAuthEvent) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_optional_fields_match_the_upstream_event_shape() {
        let event = AgentAuthEvent::Audit(Box::new(AgentAuthAuditEvent {
            r#type: AgentAuthAuditEventType::HostCreated,
            fields: AgentAuthEventFields {
                host_id: Some("host-1".into()),
                ..AgentAuthEventFields::default()
            },
        }));
        assert_eq!(
            serde_json::to_value(event).unwrap(),
            serde_json::json!({"type":"host.created", "hostId":"host-1"})
        );
    }
}
