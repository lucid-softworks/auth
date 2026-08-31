use crate::{AuthError, AuthUser, OAuthTokens};
use async_trait::async_trait;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SsoOrganizationRole {
    #[default]
    Member,
    Admin,
}

impl SsoOrganizationRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoOrganizationProvisioningOptions {
    pub disabled: bool,
    pub default_role: SsoOrganizationRole,
}

impl Default for SsoOrganizationProvisioningOptions {
    fn default() -> Self {
        Self {
            disabled: false,
            default_role: SsoOrganizationRole::Member,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SsoOrganizationRoleInput {
    pub user: AuthUser,
    pub user_info: Map<String, Value>,
    pub tokens: Option<OAuthTokens>,
    pub provider: super::SsoProvider,
}

#[async_trait]
pub trait SsoOrganizationRoleResolver: Send + Sync {
    async fn role(&self, input: SsoOrganizationRoleInput)
    -> Result<SsoOrganizationRole, AuthError>;
}

#[cfg(feature = "axum")]
pub(super) async fn assign_from_provider(
    service: &crate::AuthService,
    plugin: &super::SsoPlugin,
    user: &AuthUser,
    user_info: &crate::OAuthUserInfo,
    tokens: Option<OAuthTokens>,
    provider: &super::SsoProvider,
) -> Result<(), AuthError> {
    assign(
        service,
        plugin,
        user,
        user_info.profile.clone(),
        tokens,
        provider,
    )
    .await
}

#[cfg(feature = "axum")]
impl crate::AuthService {
    pub(crate) async fn assign_sso_organization_by_domain(
        &self,
        user: &AuthUser,
    ) -> Result<(), AuthError> {
        let Some(plugin) = self.sso_plugin() else {
            return Ok(());
        };
        if !plugin.options().domain_verification || !user.email_verified {
            return Ok(());
        }
        let Some(domain) = email_domain(&user.email) else {
            return Ok(());
        };
        let mut providers = plugin
            .store()
            .list()
            .await
            .map_err(|error| AuthError::Storage(error.to_string()))?
            .into_iter()
            .filter(|provider| {
                provider.domain_verified == Some(true)
                    && provider.organization_id.is_some()
                    && domain_matches(&domain, &provider.domain)
            })
            .collect::<Vec<_>>();
        let organizations = providers
            .iter()
            .filter_map(|provider| provider.organization_id.as_deref())
            .collect::<std::collections::BTreeSet<_>>();
        if organizations.len() > 1 {
            tracing::warn!(
                domain,
                user_id = %user.id,
                "skipped SSO organization provisioning because a verified domain maps to multiple organizations"
            );
            return Ok(());
        }
        providers.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        let Some(provider) = providers.first() else {
            return Ok(());
        };
        assign(self, plugin, user, Map::new(), None, provider).await
    }
}

#[cfg(feature = "axum")]
async fn assign(
    service: &crate::AuthService,
    plugin: &super::SsoPlugin,
    user: &AuthUser,
    user_info: Map<String, Value>,
    tokens: Option<OAuthTokens>,
    provider: &super::SsoProvider,
) -> Result<(), AuthError> {
    if plugin.options().organization_provisioning.disabled {
        return Ok(());
    }
    let Some(organization_id) = provider.organization_id.as_deref() else {
        return Ok(());
    };
    let Ok(organization) = service.organization_plugin() else {
        return Ok(());
    };
    if organization
        .store
        .find_member(organization_id, &user.id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    let now = chrono::Utc::now();
    if organization
        .store
        .list_user_invitations(&user.email)
        .await?
        .into_iter()
        .any(|invitation| {
            invitation.organization_id == organization_id
                && invitation.status == crate::OrganizationInvitationStatus::Pending
                && invitation.expires_at > now
        })
    {
        return Ok(());
    }
    let role = match plugin.organization_role_resolver() {
        Some(resolver) => {
            resolver
                .role(SsoOrganizationRoleInput {
                    user: user.clone(),
                    user_info,
                    tokens,
                    provider: provider.clone(),
                })
                .await?
        }
        None => plugin.options().organization_provisioning.default_role,
    };
    let plan = service.database_id_plan("member", crate::DatabaseIdInput::Absent, false);
    let id = || service.prepare_database_id(&plan);
    organization
        .store
        .raw_insert_member(
            crate::OrganizationMember {
                id: String::new(),
                organization_id: organization_id.to_owned(),
                user_id: user.id.clone(),
                role: role.as_str().into(),
                created_at: now,
            },
            &id,
        )
        .await?;
    Ok(())
}

#[cfg(feature = "axum")]
fn email_domain(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    let (local, domain) = email.split_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || domain.contains(['/', '\\', ':'])
        || domain.contains('@')
    {
        return None;
    }
    hostname(domain)
}

#[cfg(feature = "axum")]
fn domain_matches(search: &str, configured: &str) -> bool {
    configured.split(',').filter_map(hostname).any(|domain| {
        search == domain || search.ends_with(&format!(".{domain}"))
    })
}

#[cfg(feature = "axum")]
fn hostname(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    url::Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .or_else(|| {
            url::Url::parse(&format!("https://{value}"))
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
        })
        .map(|hostname| hostname.to_lowercase())
}

#[cfg(all(test, feature = "axum"))]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, MemoryOrganizationStore, MemorySsoStore, MemoryStore, NewSsoProvider,
        OrganizationCreateOutcome, OrganizationDataStore, OrganizationInvitation,
        OrganizationInvitationStatus, OrganizationInvitationStore, OrganizationMember,
        OrganizationMemberStore, OrganizationPlugin, PreparedDatabaseId, SsoOptions, SsoPlugin,
        SsoProviderUpdate, SsoStore,
    };
    use chrono::{Duration, Utc};
    use std::sync::Arc;

    #[tokio::test]
    async fn verified_domain_assignment_skips_ambiguity_and_pending_invitations() {
        let (service, providers, organizations) = fixture().await;
        let user = user("employee", "employee@staff.example.com");

        service
            .assign_sso_organization_by_domain(&user)
            .await
            .unwrap();
        assert!(organizations.find_member("org-a", &user.id).await.unwrap().is_none());
        assert!(organizations.find_member("org-b", &user.id).await.unwrap().is_none());

        providers
            .update(
                "row-b",
                SsoProviderUpdate {
                    domain: Some("other.example".into()),
                    ..SsoProviderUpdate::default()
                },
            )
            .await
            .unwrap();
        create_invitation(&organizations, &user.email).await;
        service
            .assign_sso_organization_by_domain(&user)
            .await
            .unwrap();
        assert!(organizations.find_member("org-a", &user.id).await.unwrap().is_none());

        let invitation = organizations
            .list_user_invitations(&user.email)
            .await
            .unwrap()
            .pop()
            .unwrap();
        organizations
            .set_invitation_status(&invitation.id, OrganizationInvitationStatus::Canceled)
            .await
            .unwrap();
        service
            .assign_sso_organization_by_domain(&user)
            .await
            .unwrap();
        let member = organizations
            .find_member("org-a", &user.id)
            .await
            .unwrap()
            .expect("unambiguous verified domain membership");
        assert_eq!(member.role, "member");
    }

    async fn fixture() -> (
        crate::AuthService,
        Arc<MemorySsoStore>,
        Arc<MemoryOrganizationStore>,
    ) {
        let providers = Arc::new(MemorySsoStore::new());
        let organizations = Arc::new(MemoryOrganizationStore::default());
        create_organization(&organizations, "org-a", "owner-a").await;
        create_organization(&organizations, "org-b", "owner-b").await;
        for (row, provider_id, organization_id) in [
            ("row-a", "a-provider", "org-a"),
            ("row-b", "b-provider", "org-b"),
        ] {
            providers
                .create(NewSsoProvider {
                    id: row.into(),
                    issuer: format!("https://{provider_id}.example"),
                    oidc_config: None,
                    saml_config: None,
                    user_id: "owner".into(),
                    provider_id: provider_id.into(),
                    organization_id: Some(organization_id.into()),
                    domain: "example.com".into(),
                    domain_verified: Some(true),
                    additional_fields: Map::new(),
                })
                .await
                .unwrap();
        }
        let mut config = AuthConfig::new([71; 32]).unwrap();
        config
            .add_plugin(SsoPlugin::with_store(
                SsoOptions {
                    domain_verification: true,
                    ..SsoOptions::default()
                },
                providers.clone(),
            ))
            .unwrap();
        config
            .add_plugin(OrganizationPlugin::new(organizations.clone()))
            .unwrap();
        let service = crate::AuthService::new(Arc::new(MemoryStore::default()), config);
        (service, providers, organizations)
    }

    async fn create_organization(
        store: &MemoryOrganizationStore,
        organization_id: &str,
        owner_id: &str,
    ) {
        let mut organization = crate::Organization {
            id: String::new(),
            name: organization_id.into(),
            slug: organization_id.into(),
            logo: None,
            metadata: None,
            created_at: Utc::now(),
        };
        let mut owner = OrganizationMember {
            id: String::new(),
            organization_id: String::new(),
            user_id: owner_id.into(),
            role: "owner".into(),
            created_at: Utc::now(),
        };
        let organization_id = organization_id.to_owned();
        let owner_member_id = format!("member-{owner_id}");
        assert_eq!(
            store
                .create_organization(
                    &mut organization,
                    &move || Ok(id(&organization_id)),
                    &mut owner,
                    &move || Ok(id(&owner_member_id)),
                    None,
                    None,
                )
                .await
                .unwrap(),
            OrganizationCreateOutcome::Created
        );
    }

    async fn create_invitation(store: &MemoryOrganizationStore, email: &str) {
        let mut invitation = OrganizationInvitation {
            id: String::new(),
            organization_id: "org-a".into(),
            email: email.into(),
            role: "member".into(),
            status: OrganizationInvitationStatus::Pending,
            team_id: None,
            inviter_id: "owner-a".into(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
        };
        store
            .create_invitation(
                &mut invitation,
                &|| Ok(id("pending-invitation")),
                100,
                100,
                false,
            )
            .await
            .unwrap();
    }

    fn id(value: &str) -> PreparedDatabaseId {
        PreparedDatabaseId::Value(crate::DatabaseIdValue::String(value.into()))
    }

    fn user(id: &str, email: &str) -> AuthUser {
        let now = Utc::now();
        AuthUser {
            id: id.into(),
            username: None,
            display_username: None,
            name: id.into(),
            email: email.into(),
            email_verified: true,
            image: None,
            additional_fields: Map::new(),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        }
    }
}
