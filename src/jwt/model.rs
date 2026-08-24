use chrono::{DateTime, Utc};

/// One persisted Better Auth JWT signing key.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredJwk {
    pub id: String,
    pub public_key: String,
    pub private_key: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub alg: Option<String>,
    pub crv: Option<String>,
}

/// Data supplied to a JWT adapter when a new key is lazily provisioned.
#[derive(Clone, PartialEq, Eq)]
pub struct NewJwk {
    pub public_key: String,
    pub private_key: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub alg: Option<String>,
    pub crv: Option<String>,
}

impl std::fmt::Debug for StoredJwk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredJwk")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("alg", &self.alg)
            .field("crv", &self.crv)
            .finish()
    }
}

impl std::fmt::Debug for NewJwk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewJwk")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("alg", &self.alg)
            .field("crv", &self.crv)
            .finish()
    }
}
