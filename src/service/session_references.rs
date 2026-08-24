use super::{
    AuthService,
    session_storage::{storage_json, ttl_from_millis},
};
use crate::AuthError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SessionReference {
    pub(super) token: String,
    expires_at: i64,
}

impl AuthService {
    pub(super) async fn active_references(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SessionReference>, AuthError> {
        let Some(secondary) = &self.config.secondary_storage else {
            return Ok(Vec::new());
        };
        let Some(value) = secondary.get(&active_key(user_id)).await? else {
            return Ok(Vec::new());
        };
        let now = Utc::now().timestamp_millis();
        let Ok(mut references) = serde_json::from_str::<Vec<SessionReference>>(&value) else {
            return Ok(Vec::new());
        };
        references.retain(|reference| reference.expires_at > now);
        Ok(references)
    }

    pub(super) async fn add_active_reference(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let secondary = self
            .config
            .secondary_storage
            .as_ref()
            .expect("secondary storage was checked");
        let mut references = self.active_references(user_id).await?;
        references.retain(|reference| reference.token != token);
        references.push(SessionReference {
            token: token.into(),
            expires_at: expires_at.timestamp_millis(),
        });
        references.sort_by_key(|reference| reference.expires_at);
        let furthest = references
            .last()
            .map(|reference| reference.expires_at)
            .unwrap_or_default();
        secondary
            .set(
                &active_key(user_id),
                serde_json::to_string(&references).map_err(storage_json)?,
                Some(ttl_from_millis(furthest)),
            )
            .await
    }

    pub(super) async fn remove_active_reference(
        &self,
        user_id: Uuid,
        token: &str,
    ) -> Result<(), AuthError> {
        let secondary = self
            .config
            .secondary_storage
            .as_ref()
            .expect("secondary storage was checked");
        let mut references = self.active_references(user_id).await?;
        references.retain(|reference| reference.token != token);
        let key = active_key(user_id);
        if let Some(furthest) = references.last().map(|reference| reference.expires_at) {
            secondary
                .set(
                    &key,
                    serde_json::to_string(&references).map_err(storage_json)?,
                    Some(ttl_from_millis(furthest)),
                )
                .await
        } else {
            secondary.delete(&key).await
        }
    }
}

fn active_key(user_id: Uuid) -> String {
    format!("active-sessions-{user_id}")
}

pub(super) fn session_id_key(session_id: Uuid) -> String {
    format!("session-id:{session_id}")
}
