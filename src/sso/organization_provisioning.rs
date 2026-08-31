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
    #[cfg(feature = "axum")]
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
mod organization_contract;
