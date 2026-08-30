use super::super::events::TeamObservation;
use crate::{
    AuthError, AuthService, AuthUser, Organization, OrganizationMember, OrganizationPlugin,
};

pub(super) async fn after_creation(
    service: &AuthService,
    plugin: &OrganizationPlugin,
    organization: &Organization,
    member: &OrganizationMember,
    default_team_id: Option<&str>,
    user: &AuthUser,
) -> Result<(), AuthError> {
    service.observe_member_added(organization, member, user).await;
    if let Some(hooks) = &plugin.config.hooks {
        hooks.after_add_member(member, user, organization).await?;
    }
    if let Some(stripe) = service.organization_stripe_plugin() {
        stripe
            .after_organization_member_change(organization, plugin.store.as_ref())
            .await;
    }
    if let Some(team_id) = default_team_id
        && let Some(team) = plugin.store.find_team(team_id).await?
    {
        service
            .observe_team(TeamObservation::Created, organization, &team, user)
            .await;
        if let Some(hooks) = &plugin.config.hooks {
            hooks.after_create_team(&team, user, organization).await?;
        }
    }
    service.observe_organization_created(organization, user).await;
    if let Some(hooks) = &plugin.config.hooks {
        hooks.after_create(organization, member, user).await?;
    }
    Ok(())
}
