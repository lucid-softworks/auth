use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How strongly a session's subject was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    Anonymous,
    Password,
    PasswordPendingPasskey,
    Passkey,
    PasswordAndPasskey,
    Recovery,
}

impl Assurance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Password => "password",
            Self::PasswordPendingPasskey => "password_pending_passkey",
            Self::Passkey => "passkey",
            Self::PasswordAndPasskey => "password_and_passkey",
            Self::Recovery => "recovery",
        }
    }

    /// Whether this assurance proves possession of a second factor.
    pub const fn is_strong(self) -> bool {
        matches!(
            self,
            Self::Passkey | Self::PasswordAndPasskey | Self::Recovery
        )
    }

    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "anonymous" => Self::Anonymous,
            "passkey" => Self::Passkey,
            "password_pending_passkey" => Self::PasswordPendingPasskey,
            "password_and_passkey" => Self::PasswordAndPasskey,
            "recovery" => Self::Recovery,
            _ => Self::Password,
        }
    }
}

/// A user account independent of any HTTP or application framework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub role: String,
    pub is_anonymous: bool,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input used by a host to provision or update a closed-registration account.
#[derive(Debug, Clone)]
pub struct NewPasswordUser {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password: String,
    pub role: String,
}

/// A persisted WebAuthn credential owned by one account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredPasskey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: Option<String>,
    pub credential_id: String,
    pub credential: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A time-bounded capability grant that can be exchanged for a guest session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestGrant {
    pub id: Uuid,
    pub label: String,
    #[serde(skip_serializing)]
    pub token_hash: Option<String>,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<i32>,
    pub uses: i32,
    pub created_by: Uuid,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for issuing an owner-controlled guest capability.
#[derive(Debug, Clone)]
pub struct NewGuestGrant {
    pub label: String,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<i32>,
}

/// A guest grant plus its one-time-visible bearer token.
#[derive(Debug, Clone)]
pub struct IssuedGuestGrant {
    pub grant: GuestGrant,
    pub token: String,
}

/// Security-relevant action retained for owner review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub actor_user_id: Option<Uuid>,
    pub subject_user_id: Option<Uuid>,
    pub action: String,
    pub target: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Server-side session metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub actor_user_id: Option<Uuid>,
    pub guest_grant_id: Option<Uuid>,
    pub assurance: Assurance,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionWithUser {
    pub session: AuthSession,
    pub user: AuthUser,
}

/// Identity information passed to the host application's authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub actor_id: Uuid,
    pub subject_id: Uuid,
    pub session_id: Uuid,
    pub role: String,
    pub assurance: Assurance,
    pub guest_grant_id: Option<Uuid>,
    pub permissions: Vec<String>,
    pub resource_scopes: Vec<String>,
    /// When the credentials establishing the current assurance were verified.
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SessionWithUser {
    pub fn principal(&self) -> Principal {
        Principal {
            actor_id: self.session.actor_user_id.unwrap_or(self.user.id),
            subject_id: self.user.id,
            session_id: self.session.id,
            role: self.user.role.clone(),
            assurance: self.session.assurance,
            guest_grant_id: self.session.guest_grant_id,
            permissions: Vec::new(),
            resource_scopes: Vec::new(),
            authenticated_at: self.session.created_at,
            expires_at: self.session.expires_at,
        }
    }
}
