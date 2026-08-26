use super::{AuditEvent, AuditStore};
use crate::AuthError;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
#[cfg(test)]
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct MemoryAuditStore {
    events: Arc<RwLock<Vec<AuditEvent>>>,
}

#[async_trait]
impl AuditStore for MemoryAuditStore {
    async fn record_audit_event(&self, event: AuditEvent, retain: usize) -> Result<(), AuthError> {
        let mut events = self.events.write().await;
        events.push(event);
        events.sort_by_key(|event| (event.created_at, event.id));
        let remove = events.len().saturating_sub(retain);
        if remove > 0 {
            events.drain(..remove);
        }
        Ok(())
    }

    async fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, AuthError> {
        Ok(self
            .events
            .read()
            .await
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect())
    }

    async fn anonymize_user(&self, user_id: &str) -> Result<(), AuthError> {
        for event in self.events.write().await.iter_mut() {
            if event.actor_user_id.as_deref() == Some(user_id) {
                event.actor_user_id = None;
            }
            if event.subject_user_id.as_deref() == Some(user_id) {
                event.subject_user_id = None;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditMetadata, AuditOutcome};
    use chrono::Utc;
    use serde_json::json;

    #[tokio::test]
    async fn retention_and_listing_have_a_stable_total_order() {
        let store = MemoryAuditStore::default();
        let created_at = Utc::now();
        for value in [2, 1, 3] {
            store
                .record_audit_event(
                    AuditEvent {
                        id: Uuid::from_u128(value),
                        actor_user_id: None,
                        subject_user_id: None,
                        action: format!("test.{value}"),
                        target: None,
                        outcome: AuditOutcome::Success,
                        metadata: AuditMetadata::new(json!({})).unwrap(),
                        created_at,
                    },
                    2,
                )
                .await
                .unwrap();
        }
        let events = store.list_audit_events(10).await.unwrap();
        assert_eq!(
            events.into_iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![Uuid::from_u128(3), Uuid::from_u128(2)]
        );
    }
}
