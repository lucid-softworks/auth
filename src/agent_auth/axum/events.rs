use crate::{AgentAuthConfig, AgentAuthEvent};

pub(in crate::agent_auth::axum) fn emit(config: &AgentAuthConfig, event: AgentAuthEvent) {
    let Some(callback) = config.on_event.clone() else {
        return;
    };
    tokio::spawn(async move {
        if let Err(error) = callback.call(event).await {
            eprintln!("[agent-auth] onEvent callback failed: {error}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentAuthAuditEvent, AgentAuthAuditEventType, AgentAuthEventFields, AgentEventCallback,
    };
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct FailingCallback(Arc<AtomicUsize>);

    #[async_trait]
    impl AgentEventCallback for FailingCallback {
        async fn call(&self, _: AgentAuthEvent) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err("delivery failed".into())
        }
    }

    #[tokio::test]
    async fn callback_errors_are_isolated_from_the_emitting_request() {
        let calls = Arc::new(AtomicUsize::new(0));
        let config = AgentAuthConfig {
            on_event: Some(Arc::new(FailingCallback(calls.clone()))),
            ..AgentAuthConfig::default()
        };
        emit(
            &config,
            AgentAuthEvent::Audit(Box::new(AgentAuthAuditEvent {
                r#type: AgentAuthAuditEventType::HostCreated,
                fields: AgentAuthEventFields::default(),
            })),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("event callback should be scheduled");
    }
}
