use super::{AuditEvent, AuditMetadata, AuditOutcome, AuditPlugin};
use crate::AuthActivity;
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) async fn record(plugin: &AuditPlugin, activity: &AuthActivity) {
    let Some(mapped) = map(activity) else {
        return;
    };
    let Ok(metadata) = AuditMetadata::new(mapped.metadata) else {
        return;
    };
    let _ = plugin
        .store
        .record_audit_event(
            AuditEvent {
                id: Uuid::new_v4(),
                actor_user_id: mapped.actor_user_id,
                subject_user_id: mapped.subject_user_id,
                action: mapped.action.into(),
                target: mapped.target,
                outcome: AuditOutcome::Success,
                metadata,
                created_at: Utc::now(),
            },
            plugin.max_events,
        )
        .await;
}

struct MappedActivity {
    actor_user_id: Option<String>,
    subject_user_id: Option<String>,
    action: &'static str,
    target: Option<String>,
    metadata: Value,
}

fn mapped(
    actor_user_id: Option<String>,
    subject_user_id: Option<String>,
    action: &'static str,
    target: Option<String>,
    metadata: Value,
) -> MappedActivity {
    MappedActivity {
        actor_user_id,
        subject_user_id,
        action,
        target,
        metadata,
    }
}

fn map(activity: &AuthActivity) -> Option<MappedActivity> {
    map_admin(activity)
        .or_else(|| map_account_security(activity))
        .or_else(|| map_extensions(activity))
}

fn map_admin(activity: &AuthActivity) -> Option<MappedActivity> {
    map_user_state(activity)
        .or_else(|| map_admin_accounts(activity))
        .or_else(|| map_impersonation(activity))
}

fn map_user_state(activity: &AuthActivity) -> Option<MappedActivity> {
    let mapped = match activity {
        AuthActivity::UserRoleChanged {
            actor_user_id,
            user_id,
            previous_role,
            new_role,
        } => mapped(
            Some(actor_user_id.clone()),
            Some(user_id.clone()),
            "user.role.changed",
            Some(user_id.to_string()),
            json!({ "from": previous_role, "to": new_role }),
        ),
        AuthActivity::UserBanned {
            actor_user_id,
            user_id,
            reason,
            expires_at,
        } => mapped(
            Some(actor_user_id.clone()),
            Some(user_id.clone()),
            "user.banned",
            Some(user_id.to_string()),
            json!({ "reason": reason, "expiresAt": expires_at }),
        ),
        AuthActivity::UserUnbanned {
            actor_user_id,
            user_id,
        } => mapped(
            Some(actor_user_id.clone()),
            Some(user_id.clone()),
            "user.unbanned",
            Some(user_id.to_string()),
            json!({}),
        ),
        _ => return None,
    };
    Some(mapped)
}

fn map_admin_accounts(activity: &AuthActivity) -> Option<MappedActivity> {
    let mapped = match activity {
        AuthActivity::UserSessionsRevoked {
            actor_user_id,
            user_id,
        } => mapped(
            Some(actor_user_id.clone()),
            Some(user_id.clone()),
            "session.user_revoked",
            Some(user_id.to_string()),
            json!({}),
        ),
        AuthActivity::UserCreated {
            actor_user_id,
            user_id,
            role,
            username,
        } => mapped(
            Some(actor_user_id.clone()),
            Some(user_id.clone()),
            "user.created",
            Some(user_id.to_string()),
            json!({ "role": role, "username": username }),
        ),
        AuthActivity::AdministratorResetPassword {
            actor_user_id,
            user_id,
        } => mapped(
            Some(actor_user_id.clone()),
            Some(user_id.clone()),
            "password.reset_by_owner",
            Some(user_id.to_string()),
            json!({}),
        ),
        AuthActivity::UserRemoved {
            actor_user_id,
            user_id,
            name,
            role,
            username,
        } => mapped(
            Some(actor_user_id.clone()),
            None,
            "user.removed",
            Some(user_id.to_string()),
            json!({ "name": name, "role": role, "username": username }),
        ),
        _ => return None,
    };
    Some(mapped)
}

fn map_impersonation(activity: &AuthActivity) -> Option<MappedActivity> {
    let mapped = match activity {
        AuthActivity::ImpersonationStarted {
            actor_user_id,
            user_id,
            session_id,
            expires_at,
        } => mapped(
            Some(actor_user_id.clone()),
            Some(user_id.clone()),
            "impersonation.started",
            Some(session_id.to_string()),
            json!({ "expiresAt": expires_at }),
        ),
        AuthActivity::ImpersonationStopped {
            actor_user_id,
            user_id,
            session_id,
        } => mapped(
            Some(actor_user_id.clone()),
            Some(user_id.clone()),
            "impersonation.stopped",
            Some(session_id.to_string()),
            json!({}),
        ),
        _ => return None,
    };
    Some(mapped)
}

fn map_account_security(activity: &AuthActivity) -> Option<MappedActivity> {
    map_sessions(activity).or_else(|| map_credentials(activity))
}

fn map_sessions(activity: &AuthActivity) -> Option<MappedActivity> {
    let mapped = match activity {
        AuthActivity::SessionRevoked {
            actor_user_id,
            subject_user_id,
            session_id,
            self_service,
        } => mapped(
            Some(actor_user_id.clone()),
            subject_user_id.clone(),
            "session.revoked",
            session_id.clone(),
            if *self_service {
                json!({ "selfService": true })
            } else {
                json!({})
            },
        ),
        AuthActivity::OtherSessionsRevoked {
            user_id,
            retained_session_id,
        } => mapped(
            Some(user_id.clone()),
            Some(user_id.clone()),
            "session.others_revoked",
            Some(retained_session_id.to_string()),
            json!({}),
        ),
        AuthActivity::AllSessionsRevoked { user_id } => mapped(
            Some(user_id.clone()),
            Some(user_id.clone()),
            "session.all_revoked",
            None,
            json!({}),
        ),
        _ => return None,
    };
    Some(mapped)
}

fn map_credentials(activity: &AuthActivity) -> Option<MappedActivity> {
    let mapped = match activity {
        AuthActivity::PasswordChanged {
            user_id,
            revoked_other_sessions,
        } => mapped(
            Some(user_id.clone()),
            Some(user_id.clone()),
            "password.changed",
            None,
            json!({ "revokedOtherSessions": revoked_other_sessions }),
        ),
        AuthActivity::PasskeyRenamed {
            user_id,
            passkey_id,
            name,
        } => mapped(
            Some(user_id.clone()),
            Some(user_id.clone()),
            "passkey.renamed",
            Some(passkey_id.to_string()),
            json!({ "name": name }),
        ),
        AuthActivity::PasskeyDeleted {
            user_id,
            passkey_id,
            remaining,
        } => mapped(
            Some(user_id.clone()),
            Some(user_id.clone()),
            "passkey.deleted",
            Some(passkey_id.to_string()),
            json!({ "remaining": remaining }),
        ),
        AuthActivity::PasskeyEnrolled {
            actor_user_id,
            user_id,
            passkey_id,
        } => mapped(
            actor_user_id.clone(),
            Some(user_id.clone()),
            "passkey.enrolled",
            Some(passkey_id.to_string()),
            json!({}),
        ),
        _ => return None,
    };
    Some(mapped)
}

fn map_extensions(activity: &AuthActivity) -> Option<MappedActivity> {
    let mapped = match activity {
        AuthActivity::GuestGrantIssued {
            actor_user_id,
            grant_id,
            label,
            permissions,
            resource_scopes,
            expires_at,
            max_uses,
        } => MappedActivity {
            actor_user_id: Some(actor_user_id.clone()),
            subject_user_id: None,
            action: "guest_grant.issued",
            target: Some(grant_id.to_string()),
            metadata: json!({
                "label": label,
                "permissions": permissions,
                "resourceScopes": resource_scopes,
                "expiresAt": expires_at,
                "maxUses": max_uses,
            }),
        },
        AuthActivity::GuestGrantRedeemed {
            user_id,
            grant_id,
            label,
            uses,
        } => MappedActivity {
            actor_user_id: None,
            subject_user_id: Some(user_id.clone()),
            action: "guest_grant.redeemed",
            target: Some(grant_id.to_string()),
            metadata: json!({ "label": label, "uses": uses }),
        },
        AuthActivity::GuestGrantRevoked {
            actor_user_id,
            grant_id,
        } => MappedActivity {
            actor_user_id: Some(actor_user_id.clone()),
            subject_user_id: None,
            action: "guest_grant.revoked",
            target: Some(grant_id.to_string()),
            metadata: json!({}),
        },
        AuthActivity::SoleOwnerRecovered { user_id } => MappedActivity {
            actor_user_id: None,
            subject_user_id: Some(user_id.clone()),
            action: "operator_security.owner_recovered",
            target: Some(user_id.to_string()),
            metadata: json!({
                "sessionsRevoked": true,
                "factorsReset": true,
                "replacementRequired": true,
            }),
        },
        AuthActivity::StepUpRecoveryCodesGenerated { user_id, count } => MappedActivity {
            actor_user_id: Some(user_id.clone()),
            subject_user_id: Some(user_id.clone()),
            action: "step_up.recovery_codes.generated",
            target: None,
            metadata: json!({ "count": count }),
        },
        AuthActivity::StepUpRecoveryCodeUsed {
            user_id,
            session_id,
            remaining,
        } => MappedActivity {
            actor_user_id: Some(user_id.clone()),
            subject_user_id: Some(user_id.clone()),
            action: "step_up.recovery_code.used",
            target: Some(session_id.to_string()),
            metadata: json!({ "remaining": remaining }),
        },
        _ => return None,
    };
    Some(mapped)
}
