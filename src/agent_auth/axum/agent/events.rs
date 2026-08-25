use crate::{
    AgentAuthAuditEvent, AgentAuthAuditEventType, AgentAuthEvent, AgentAuthEventFields,
    agent_auth::axum::AgentAuthState,
};
use serde_json::{Map, Value};

pub(super) async fn emit(
    state: &AgentAuthState,
    r#type: AgentAuthAuditEventType,
    actor_id: Option<String>,
    actor_type: Option<&str>,
    agent_id: Option<String>,
    host_id: Option<String>,
    metadata: Option<Map<String, Value>>,
) {
    super::super::events::emit(
        &state.config,
        AgentAuthEvent::Audit(Box::new(AgentAuthAuditEvent {
            r#type,
            fields: AgentAuthEventFields {
                actor_id,
                actor_type: actor_type.map(str::to_owned),
                agent_id,
                host_id,
                metadata,
                ..AgentAuthEventFields::default()
            },
        })),
    );
}
