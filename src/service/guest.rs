use super::{AuthService, hash_token, random_token};
use crate::{
    Assurance, AuditEvent, AuthError, AuthUser, GuestCapabilityPlugin, GuestCapabilityPrincipal,
    GuestGrant, GuestGrantSignInResult, IssuedGuestGrant, NewGuestGrant,
};
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

impl AuthService {
    pub async fn issue_guest_grant(
        &self,
        actor: &crate::SessionWithUser,
        mut input: NewGuestGrant,
    ) -> Result<IssuedGuestGrant, AuthError> {
        let store = self.guest_capability()?.store.clone();
        self.require_recent_owner(actor)?;
        validate_guest_grant(&input)?;
        normalize(&mut input.permissions);
        normalize(&mut input.resource_scopes);

        let token = random_token();
        let now = Utc::now();
        let grant = store
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
    ) -> Result<GuestGrantSignInResult, AuthError> {
        let store = self.guest_capability()?.store.clone();
        if token.len() < 32 || token.len() > 256 {
            return Err(AuthError::InvalidGuestGrant);
        }
        let now = Utc::now();
        let grant = store
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
                must_change_password: false,
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
                Some(grant.expires_at),
                ip_address,
                user_agent,
            )
            .await?;
        if !store
            .attach_guest_session(grant.id, result.session.session.id, Utc::now())
            .await?
        {
            self.store.delete_user(result.session.user.id).await?;
            return Err(AuthError::InvalidGuestGrant);
        }
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
        Ok(GuestGrantSignInResult::new(result, grant.id))
    }

    pub async fn guest_capability_principal(
        &self,
        token: &str,
    ) -> Result<Option<GuestCapabilityPrincipal>, AuthError> {
        let store = self.guest_capability()?.store.clone();
        let Some(session) = self.session(token).await? else {
            return Ok(None);
        };
        let Some(grant) = store
            .find_guest_grant_for_session(session.session.id)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(GuestCapabilityPrincipal {
            principal: session.principal(),
            guest_grant_id: grant.id,
            permissions: grant.permissions,
            resource_scopes: grant.resource_scopes,
        }))
    }

    pub async fn list_guest_grants(
        &self,
        actor: &crate::SessionWithUser,
    ) -> Result<Vec<GuestGrant>, AuthError> {
        let store = self.guest_capability()?.store.clone();
        super::access::require_owner(actor)?;
        store.list_guest_grants().await
    }

    pub async fn revoke_guest_grant(
        &self,
        actor: &crate::SessionWithUser,
        grant_id: Uuid,
    ) -> Result<(), AuthError> {
        let store = self.guest_capability()?.store.clone();
        self.require_recent_owner(actor)?;
        store.revoke_guest_grant(grant_id, Utc::now()).await?;
        self.audit(
            actor.user.id,
            None,
            "guest_grant.revoked",
            Some(grant_id.to_string()),
            json!({}),
        )
        .await
    }

    fn guest_capability(&self) -> Result<&GuestCapabilityPlugin, AuthError> {
        self.plugins
            .find::<GuestCapabilityPlugin>()
            .ok_or(AuthError::NotFound)
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
    use crate::{AuthConfig, GuestCapabilityPlugin, MemoryStore, NewPasswordUser};
    use std::sync::Arc;

    async fn fixture() -> (Arc<AuthService>, crate::SessionWithUser) {
        let store = Arc::new(MemoryStore::default());
        let mut config = AuthConfig::new([9_u8; 32]).unwrap();
        config
            .add_plugin(GuestCapabilityPlugin::new(store.clone()))
            .unwrap();
        let service = Arc::new(AuthService::new(store, config));
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
        (service, owner.session)
    }

    #[tokio::test]
    async fn max_use_redemption_and_revocation_are_atomic() {
        let (service, owner) = fixture().await;
        let now = Utc::now();
        let issued = service
            .issue_guest_grant(
                &owner,
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
        let (left, right) = tokio::join!(
            service.redeem_guest_grant(&issued.token, None, None),
            service.redeem_guest_grant(&issued.token, None, None),
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let redeemed = left.or(right).unwrap();
        let principal = service
            .guest_capability_principal(&redeemed.token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(principal.permissions, ["devices:read"]);
        assert_eq!(principal.resource_scopes, ["room:kitchen"]);
        service
            .revoke_guest_grant(&owner, issued.grant.id)
            .await
            .unwrap();
        assert!(service.session(&redeemed.token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn future_grants_cannot_be_redeemed_early() {
        let (service, owner) = fixture().await;
        let now = Utc::now();
        let issued = service
            .issue_guest_grant(
                &owner,
                NewGuestGrant {
                    label: "Future guest".into(),
                    permissions: vec!["devices:read".into()],
                    resource_scopes: Vec::new(),
                    valid_from: now + Duration::hours(1),
                    expires_at: now + Duration::hours(2),
                    max_uses: None,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            service.redeem_guest_grant(&issued.token, None, None).await,
            Err(AuthError::InvalidGuestGrant)
        ));
    }
}
