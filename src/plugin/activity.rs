use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Successful authentication-domain activity observed by optional plugins.
///
/// Variants describe native operations without assigning an external action
/// name or wire representation. An observer plugin owns that vocabulary.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AuthActivity {
    UserRoleChanged {
        actor_user_id: Uuid,
        user_id: Uuid,
        previous_role: String,
        new_role: String,
    },
    UserBanned {
        actor_user_id: Uuid,
        user_id: Uuid,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    },
    UserUnbanned {
        actor_user_id: Uuid,
        user_id: Uuid,
    },
    SessionRevoked {
        actor_user_id: Uuid,
        subject_user_id: Option<Uuid>,
        session_id: Option<Uuid>,
        self_service: bool,
    },
    UserSessionsRevoked {
        actor_user_id: Uuid,
        user_id: Uuid,
    },
    ImpersonationStarted {
        actor_user_id: Uuid,
        user_id: Uuid,
        session_id: Uuid,
        expires_at: DateTime<Utc>,
    },
    ImpersonationStopped {
        actor_user_id: Uuid,
        user_id: Uuid,
        session_id: Uuid,
    },
    UserCreated {
        actor_user_id: Uuid,
        user_id: Uuid,
        role: String,
        username: Option<String>,
    },
    AdministratorResetPassword {
        actor_user_id: Uuid,
        user_id: Uuid,
    },
    UserRemoved {
        actor_user_id: Uuid,
        user_id: Uuid,
        name: String,
        role: String,
        username: Option<String>,
    },
    PasswordChanged {
        user_id: Uuid,
        revoked_other_sessions: bool,
    },
    OtherSessionsRevoked {
        user_id: Uuid,
        retained_session_id: Uuid,
    },
    AllSessionsRevoked {
        user_id: Uuid,
    },
    PasskeyRenamed {
        user_id: Uuid,
        passkey_id: Uuid,
        name: String,
    },
    PasskeyDeleted {
        user_id: Uuid,
        passkey_id: Uuid,
        remaining: usize,
    },
    PasskeyEnrolled {
        actor_user_id: Option<Uuid>,
        user_id: Uuid,
        passkey_id: Uuid,
    },
    GuestGrantIssued {
        actor_user_id: Uuid,
        grant_id: Uuid,
        label: String,
        permissions: Vec<String>,
        resource_scopes: Vec<String>,
        expires_at: DateTime<Utc>,
        max_uses: Option<i32>,
    },
    GuestGrantRedeemed {
        user_id: Uuid,
        grant_id: Uuid,
        label: String,
        uses: i32,
    },
    GuestGrantRevoked {
        actor_user_id: Uuid,
        grant_id: Uuid,
    },
    SoleOwnerRecovered {
        user_id: Uuid,
    },
    StepUpRecoveryCodesGenerated {
        user_id: Uuid,
        count: usize,
    },
    StepUpRecoveryCodeUsed {
        user_id: Uuid,
        session_id: Uuid,
        remaining: usize,
    },
}
