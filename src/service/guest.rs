use super::{AuthService, SignInResult, hash_token, random_token};
use crate::{
    Assurance, AuditEvent, AuthError, AuthUser, GuestGrant, IssuedGuestGrant, NewGuestGrant,
};
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use super::access::require_owner;

impl AuthService {
    pub async fn issue_guest_grant(
        &self,
        actor: &crate::SessionWithUser,
        mut input: NewGuestGrant,
    ) -> Result<IssuedGuestGrant, AuthError> {
        require_owner(actor)?;
        validate_guest_grant(&input)?;
        normalize(&mut input.permissions);
        normalize(&mut input.resource_scopes);

        let token = random_token();
        let now = Utc::now();
        let grant = self
            .store
            .create_guest_grant(GuestGrant {
                id: Uuid::new_v4(),
                label: input.label.trim().to_owned(),
                token_hash: Some(hash_token(&token)),
                permissions: input.permissions,
                resource_scopes: input.resource_scopes,
                valid_from: input.valid_from,
                expires_at: input.expires_at,
                max_uses: input.max_uses,
                uses: 0,
                created_by: actor.user.id,
                revoked_at: None,
                created_at: now,
            })
            .await?;
        self.audit(
            actor.user.id,
            None,
            "guest_grant.issued",
            Some(grant.id.to_string()),
            json!({
                "label": grant.label,
                "permissions": grant.permissions,
                "resourceScopes": grant.resource_scopes,
                "expiresAt": grant.expires_at,
                "maxUses": grant.max_uses,
            }),
        )
        .await?;
        Ok(IssuedGuestGrant { grant, token })
    }

    pub async fn redeem_guest_grant(
        &self,
        token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        if token.len() < 32 || token.len() > 256 {
            return Err(AuthError::InvalidGuestGrant);
        }
        let now = Utc::now();
        let grant = self
            .store
            .consume_guest_grant(&hash_token(token), now)
            .await?
            .ok_or(AuthError::InvalidGuestGrant)?;
        let id = Uuid::new_v4();
        let user = self
            .store
            .create_anonymous_user(AuthUser {
                id,
                username: None,
                display_username: None,
                name: grant.label.clone(),
                email: format!("guest-{id}@users.localhost"),
                email_verified: false,
                image: None,
                role: "guest".into(),
                is_anonymous: true,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            })
            .await?;
        let result = self
            .create_session_until(
                user,
                Assurance::Anonymous,
                None,
                Some(grant.id),
                Some(grant.expires_at),
                ip_address,
                user_agent,
            )
            .await?;
        self.store
            .append_audit_event(AuditEvent {
                id: Uuid::new_v4(),
                actor_user_id: None,
                subject_user_id: Some(result.session.user.id),
                action: "guest_grant.redeemed".into(),
                target: Some(grant.id.to_string()),
                metadata: json!({ "label": grant.label, "uses": grant.uses }),
                created_at: now,
            })
            .await?;
        Ok(result)
    }

    pub async fn list_guest_grants(
        &self,
        actor: &crate::SessionWithUser,
    ) -> Result<Vec<GuestGrant>, AuthError> {
        require_owner(actor)?;
        self.store.list_guest_grants().await
    }

    pub async fn revoke_guest_grant(
        &self,
        actor: &crate::SessionWithUser,
        grant_id: Uuid,
    ) -> Result<(), AuthError> {
        require_owner(actor)?;
        self.store.revoke_guest_grant(grant_id, Utc::now()).await?;
        self.audit(
            actor.user.id,
            None,
            "guest_grant.revoked",
            Some(grant_id.to_string()),
            json!({}),
        )
        .await
    }
}

fn validate_guest_grant(input: &NewGuestGrant) -> Result<(), AuthError> {
    let label = input.label.trim();
    if label.is_empty() || label.chars().count() > 100 {
        return invalid_grant("guest grant label must contain 1 to 100 characters");
    }
    if input.permissions.is_empty() || input.permissions.len() > 64 {
        return invalid_grant("guest grants require 1 to 64 permissions");
    }
    if input.resource_scopes.len() > 128
        || !input
            .permissions
            .iter()
            .all(|value| valid_capability(value))
        || !input
            .resource_scopes
            .iter()
            .all(|value| valid_resource_scope(value))
    {
        return invalid_grant("guest grant permissions or resource scopes are invalid");
    }
    if input.expires_at <= input.valid_from
        || input.expires_at <= Utc::now()
        || input.expires_at - input.valid_from > Duration::days(365)
    {
        return invalid_grant("guest grant validity must end within one year");
    }
    if input
        .max_uses
        .is_some_and(|uses| !(1..=10_000).contains(&uses))
    {
        return invalid_grant("guest grant max uses must be between 1 and 10000");
    }
    Ok(())
}

fn valid_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b":._-".contains(&byte)
        })
}

fn valid_resource_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._-/".contains(&byte))
}

fn normalize(values: &mut Vec<String>) {
    values.sort_unstable();
    values.dedup();
}

fn invalid_grant<T>(message: &str) -> Result<T, AuthError> {
    Err(AuthError::InvalidRequest(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore, NewPasswordUser};
    use std::sync::Arc;

    #[tokio::test]
    async fn issued_guest_grants_carry_capabilities_and_can_be_revoked() {
        let service = AuthService::new(
            Arc::new(MemoryStore::default()),
            AuthConfig::new([9_u8; 32]).unwrap(),
        );
        service
            .provision_password_user(NewPasswordUser {
                username: "owner".into(),
                name: "Owner".into(),
                email: None,
                password: "password".into(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        let owner = service
            .sign_in_username("owner", "password".into(), None, None)
            .await
            .unwrap();
        let now = Utc::now();
        let issued = service
            .issue_guest_grant(
                &owner.session,
                NewGuestGrant {
                    label: "Dog sitter".into(),
                    permissions: vec!["devices:read".into(), "devices:read".into()],
                    resource_scopes: vec!["room:kitchen".into()],
                    valid_from: now,
                    expires_at: now + Duration::hours(2),
                    max_uses: Some(1),
                },
            )
            .await
            .unwrap();
        assert_eq!(issued.grant.permissions, vec!["devices:read"]);

        let guest = service
            .redeem_guest_grant(&issued.token, None, None)
            .await
            .unwrap();
        let principal = service.principal(&guest.token).await.unwrap().unwrap();
        assert_eq!(principal.permissions, vec!["devices:read"]);
        assert_eq!(principal.resource_scopes, vec!["room:kitchen"]);
        assert!(matches!(
            service.redeem_guest_grant(&issued.token, None, None).await,
            Err(AuthError::InvalidGuestGrant)
        ));

        service
            .revoke_guest_grant(&owner.session, issued.grant.id)
            .await
            .unwrap();
        assert!(service.principal(&guest.token).await.unwrap().is_none());
    }
}
