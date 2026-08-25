use crate::{
    AgentAuthAuditEvent, AgentAuthAuditEventType, AgentAuthEvent, AgentAuthEventFields,
    agent_auth::axum::AgentAuthState,
};
use serde_json::{Map, Value};

pub(super) fn emit(
    state: &AgentAuthState,
    event_type: AgentAuthAuditEventType,
    actor_id: Option<String>,
    actor_type: Option<&str>,
    host_id: String,
    metadata: Map<String, Value>,
) {
    super::super::events::emit(
        &state.config,
        AgentAuthEvent::Audit(Box::new(AgentAuthAuditEvent {
            r#type: event_type,
            fields: AgentAuthEventFields {
                actor_id,
                actor_type: actor_type.map(str::to_owned),
                host_id: Some(host_id),
                metadata: Some(metadata),
                ..AgentAuthEventFields::default()
            },
        })),
    );
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::{AgentAuthEvent, AgentEventCallback};
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::{Mutex, Notify};

    #[derive(Clone, Default)]
    pub(crate) struct EventRecorder {
        events: Arc<Mutex<Vec<AgentAuthEvent>>>,
        changed: Arc<Notify>,
    }

    impl EventRecorder {
        pub(crate) async fn wait_for(&self, count: usize) -> Vec<AgentAuthEvent> {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    let changed = self.changed.notified();
                    let events = self.events.lock().await.clone();
                    if events.len() >= count {
                        return events;
                    }
                    changed.await;
                }
            })
            .await
            .expect("expected Agent Auth events were not delivered")
        }

        pub(crate) async fn clear(&self) {
            self.events.lock().await.clear();
        }
    }

    #[async_trait]
    impl AgentEventCallback for EventRecorder {
        async fn call(&self, event: AgentAuthEvent) -> Result<(), String> {
            self.events.lock().await.push(event);
            self.changed.notify_waiters();
            Ok(())
        }
    }
}
