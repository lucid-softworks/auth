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
        actor_user_id: String,
        user_id: String,
        previous_role: String,
        new_role: String,
    },
    UserBanned {
        actor_user_id: String,
        user_id: String,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    },
    UserUnbanned {
        actor_user_id: String,
        user_id: String,
    },
    SessionRevoked {
        actor_user_id: String,
        subject_user_id: Option<String>,
        session_id: Option<String>,
        self_service: bool,
    },
    UserSessionsRevoked {
        actor_user_id: String,
        user_id: String,
    },
    ImpersonationStarted {
        actor_user_id: String,
        user_id: String,
        session_id: String,
        expires_at: DateTime<Utc>,
    },
    ImpersonationStopped {
        actor_user_id: String,
        user_id: String,
        session_id: String,
    },
    UserCreated {
        actor_user_id: String,
        user_id: String,
        role: String,
        username: Option<String>,
    },
    AdministratorResetPassword {
        actor_user_id: String,
        user_id: String,
    },
    UserRemoved {
        actor_user_id: String,
        user_id: String,
        name: String,
        role: String,
        username: Option<String>,
    },
    PasswordChanged {
        user_id: String,
        revoked_other_sessions: bool,
    },
    OtherSessionsRevoked {
        user_id: String,
        retained_session_id: String,
    },
    AllSessionsRevoked {
        user_id: String,
    },
    PasskeyRenamed {
        user_id: String,
        passkey_id: String,
        name: String,
    },
    PasskeyDeleted {
        user_id: String,
        passkey_id: String,
        remaining: usize,
    },
    PasskeyEnrolled {
        actor_user_id: Option<String>,
        user_id: String,
        passkey_id: String,
    },
    GuestGrantIssued {
        actor_user_id: String,
        grant_id: Uuid,
        label: String,
        permissions: Vec<String>,
        resource_scopes: Vec<String>,
        expires_at: DateTime<Utc>,
        max_uses: Option<i32>,
    },
    GuestGrantRedeemed {
        user_id: String,
        grant_id: Uuid,
        label: String,
        uses: i32,
    },
    GuestGrantRevoked {
        actor_user_id: String,
        grant_id: Uuid,
    },
    SoleOwnerRecovered {
        user_id: String,
    },
    StepUpRecoveryCodesGenerated {
        user_id: String,
        count: usize,
    },
    StepUpRecoveryCodeUsed {
        user_id: String,
        session_id: String,
        remaining: usize,
    },
}
