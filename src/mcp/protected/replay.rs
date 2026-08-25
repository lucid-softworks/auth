use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::McpProtectedRequestError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpDpopReplayReservation {
    pub key: String,
    pub expires_at: DateTime<Utc>,
    pub now: DateTime<Utc>,
}

#[async_trait]
pub trait McpDpopReplayStore: Send + Sync {
    async fn reserve(
        &self,
        reservation: McpDpopReplayReservation,
    ) -> Result<bool, McpProtectedRequestError>;
}

/// Single-process replay protection used by the generic verifier by default.
#[derive(Debug, Default)]
pub struct ProcessMcpDpopReplayStore {
    reservations: Mutex<HashMap<String, DateTime<Utc>>>,
}

#[async_trait]
impl McpDpopReplayStore for ProcessMcpDpopReplayStore {
    async fn reserve(
        &self,
        reservation: McpDpopReplayReservation,
    ) -> Result<bool, McpProtectedRequestError> {
        let mut reservations = self.reservations.lock().map_err(|_| {
            McpProtectedRequestError::Infrastructure("DPoP replay store lock failed".into())
        })?;
        reservations.retain(|_, expires_at| *expires_at > reservation.now);
        if reservations.contains_key(&reservation.key) {
            return Ok(false);
        }
        reservations.insert(reservation.key, reservation.expires_at);
        Ok(true)
    }
}

pub(crate) struct DurableMcpDpopReplayStore {
    service: std::sync::Arc<crate::AuthService>,
}

impl DurableMcpDpopReplayStore {
    pub(crate) fn new(service: std::sync::Arc<crate::AuthService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl McpDpopReplayStore for DurableMcpDpopReplayStore {
    async fn reserve(
        &self,
        reservation: McpDpopReplayReservation,
    ) -> Result<bool, McpProtectedRequestError> {
        self.service
            .reserve_mcp_dpop_proof(&reservation.key, reservation.expires_at)
            .await
            .map_err(|error| McpProtectedRequestError::Infrastructure(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn process_store_reserves_once_and_purges_expired_values() {
        let store = ProcessMcpDpopReplayStore::default();
        let now = Utc::now();
        let reservation = McpDpopReplayReservation {
            key: "proof".into(),
            expires_at: now + chrono::Duration::minutes(5),
            now,
        };
        assert!(store.reserve(reservation.clone()).await.unwrap());
        assert!(!store.reserve(reservation).await.unwrap());
        assert!(
            store
                .reserve(McpDpopReplayReservation {
                    key: "proof".into(),
                    expires_at: now + chrono::Duration::minutes(10),
                    now: now + chrono::Duration::minutes(6),
                })
                .await
                .unwrap()
        );
    }
}
