#[cfg(feature = "axum")]
mod axum;
mod memory;

pub use memory::MemoryAuditStore;

use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginDescriptor, PluginEndpoint, PluginHttpMethod,
    PluginMigration,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

const ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: "/access/audit",
    client_method: "lucidAudit.list",
}];

const MIGRATIONS: &[PluginMigration] = &[PluginMigration::borrowed(
    "lucid-security-audit-schema",
    "Optional lucid security-audit event storage",
    include_str!("../../migrations/audit_plugin.sql"),
)];

/// Version of the stable action-name vocabulary emitted by [`AuditPlugin`].
pub const AUDIT_ACTION_VOCABULARY_VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
}

#[cfg(feature = "postgres")]
impl AuditOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, AuthError> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            _ => Err(AuthError::Storage("audit outcome is invalid".into())),
        }
    }
}

/// Validated event metadata whose keys cannot represent common authentication secrets.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AuditMetadata(Value);

impl AuditMetadata {
    pub fn new(value: Value) -> Result<Self, AuthError> {
        if contains_secret_key(&value) {
            return Err(AuthError::InvalidRequest(
                "audit metadata contains a secret-bearing field".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn into_value(self) -> Value {
        self.0
    }
}

impl<'de> Deserialize<'de> for AuditMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Value::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: Uuid,
    pub actor_user_id: Option<Uuid>,
    pub subject_user_id: Option<Uuid>,
    pub action: String,
    pub target: Option<String>,
    pub outcome: AuditOutcome,
    pub metadata: AuditMetadata,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait AuditStore: Send + Sync {
    /// Appends an event and applies retention in the same store operation.
    async fn record_audit_event(&self, event: AuditEvent, retain: usize) -> Result<(), AuthError>;

    async fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, AuthError>;

    async fn anonymize_user(&self, user_id: Uuid) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct AuditPlugin {
    pub(crate) store: Arc<dyn AuditStore>,
    pub(crate) max_events: usize,
}

impl AuditPlugin {
    pub fn new(store: Arc<dyn AuditStore>) -> Self {
        Self {
            store,
            max_events: 10_000,
        }
    }

    pub fn with_max_events(mut self, max_events: usize) -> Self {
        self.max_events = max_events;
        self
    }
}

#[async_trait]
impl AuthPlugin for AuditPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "lucid-security-audit",
            display_name: "lucid-auth Security Audit",
            version: env!("CARGO_PKG_VERSION"),
            dependencies: &["lucid-owner-policy"],
            conflicts: &[],
            endpoints: ENDPOINTS,
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        if self.max_events == 0 {
            return Err(AuthError::InvalidConfiguration(
                "audit retention must keep at least one event".into(),
            ));
        }
        if i64::try_from(self.max_events).is_err() {
            return Err(AuthError::InvalidConfiguration(
                "audit retention exceeds PostgreSQL's supported range".into(),
            ));
        }
        Ok(())
    }

    fn migrations(&self) -> std::borrow::Cow<'_, [PluginMigration]> {
        std::borrow::Cow::Borrowed(MIGRATIONS)
    }

    async fn after(&self, event: &crate::AfterAuthEvent) {
        if let crate::AfterAuthEvent::UserDeleted { user } = event {
            let _ = self.store.anonymize_user(user.id).await;
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service)
    }
}

fn contains_secret_key(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            let normalized: String = key
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect();
            [
                "password",
                "cookie",
                "token",
                "otp",
                "secret",
                "challenge",
                "apikey",
                "credential",
                "authorization",
                "bearer",
            ]
            .iter()
            .any(|forbidden| normalized.contains(forbidden))
                || contains_secret_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret_key),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_secret_bearing_metadata_recursively() {
        assert!(AuditMetadata::new(json!({ "sessionToken": "redact-me" })).is_err());
        assert!(AuditMetadata::new(json!({ "nested": [{ "passkeyChallenge": "x" }] })).is_err());
        assert!(AuditMetadata::new(json!({ "role": "member", "uses": 1 })).is_ok());
        assert!(
            serde_json::from_value::<AuditMetadata>(json!({ "authorization": "Bearer x" }))
                .is_err()
        );
    }
}
