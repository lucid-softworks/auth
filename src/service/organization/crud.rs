use super::{AuthService, creation_persistence};
use crate::{
    AuthError, FullOrganization, NewOrganization, Organization, OrganizationCreateOutcome,
    OrganizationCreation, OrganizationError, OrganizationMember, OrganizationMemberWithUser,
    OrganizationTeam, OrganizationTeamMember, OrganizationUpdate, SessionWithUser,
};
use chrono::Utc;
use std::collections::BTreeMap;

mod events;

impl AuthService {
    pub async fn create_organization(
        &self,
        session: &SessionWithUser,
        input: NewOrganization,
    ) -> Result<OrganizationCreation, AuthError> {
        let plugin = self.organization_plugin()?;
        let policy_allowed = match &plugin.config.creation_policy {
            Some(policy) => policy.allow(&session.user).await?,
            None => plugin.config.allow_user_to_create_organization,
        };
        if !policy_allowed {
            return Err(forbidden(
                "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
                "You are not allowed to create a new organization",
            ));
        }
        let keep_current = input.keep_current_active_organization;
        let (mut organization, mut member, mut default_team) =
            prepare_creation(plugin, session, input).await?;
        match creation_persistence::create(
            self,
            plugin,
            &mut organization,
            &mut member,
            &mut default_team,
        )
        .await?
        {
            OrganizationCreateOutcome::Created => {}
            OrganizationCreateOutcome::SlugTaken => {
                return Err(bad_request(
                    "ORGANIZATION_ALREADY_EXISTS",
                    "Organization already exists",
                ));
            }
            OrganizationCreateOutcome::LimitReached => {
                return Err(forbidden(
                    "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS",
                    "You have reached the maximum number of organizations",
                ));
            }
        }
        let default_team_id = default_team.as_ref().map(|(team, _)| team.id.clone());
        events::after_creation(
            self,
            plugin,
            &organization,
            &member,
            default_team_id.as_deref(),
            &session.user,
        )
        .await?;
        if !keep_current {
            self.set_active_organization(session, Some(organization.id.clone()))
                .await?;
            if let Some(team_id) = default_team_id {
                self.set_active_team(session, Some(team_id)).await?;
            }
        }
        Ok(OrganizationCreation {
            organization,
            member,
        })
    }

    pub async fn update_organization(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        update: OrganizationUpdate,
    ) -> Result<Organization, AuthError> {
        let organization_id = organization_id
            .or_else(|| Self::active_organization_id(session))
            .ok_or_else(organization_not_found)?;
        let plugin = self.organization_plugin()?;
        let member = require_member(plugin, &organization_id, &session.user.id).await?;
        require_permission(
            self,
            &member,
            "organization",
            "update",
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
            "You are not allowed to update this organization",
        )
        .await?;
        let mut organization = plugin
            .store
            .find_organization_by_id(&organization_id)
            .await?
            .ok_or_else(organization_not_found)?;
        if let Some(name) = update.name {
            organization.name = name;
        }
        if let Some(slug) = update.slug {
            organization.slug = slug;
        }
        if let Some(logo) = update.logo {
            organization.logo = logo;
        }
        if let Some(metadata) = update.metadata {
            organization.metadata = Some(metadata);
        }
        if let Some(hooks) = &plugin.config.hooks {
            organization = hooks
                .before_update(organization, &member, &session.user)
                .await?;
        }
        let organization = plugin
            .store
            .update_organization(organization)
            .await?
            .ok_or_else(|| {
                bad_request(
                    "ORGANIZATION_SLUG_ALREADY_TAKEN",
                    "Organization slug already taken",
                )
            })?;
        self.observe_organization_updated(&organization, &session.user)
            .await;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .after_update(&organization, &member, &session.user)
                .await?;
        }
        if let Some(stripe) = self.organization_stripe_plugin() {
            stripe.after_organization_update(&organization).await;
        }
        Ok(organization)
    }

    pub async fn delete_organization(
        &self,
        session: &SessionWithUser,
        organization_id: String,
    ) -> Result<Organization, AuthError> {
        let plugin = self.organization_plugin()?;
        if plugin.config.disable_organization_deletion {
            return Err(OrganizationError::not_found(
                "ORGANIZATION_DELETION_DISABLED",
                "Organization deletion is disabled",
            )
            .into());
        }
        let member = require_member(plugin, &organization_id, &session.user.id).await?;
        require_permission(
            self,
            &member,
            "organization",
            "delete",
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
            "You are not allowed to delete this organization",
        )
        .await?;
        let organization = plugin
            .store
            .find_organization_by_id(&organization_id)
            .await?
            .ok_or_else(organization_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks.before_delete(&organization, &session.user).await?;
        }
        if let Some(stripe) = self.organization_stripe_plugin() {
            stripe.before_organization_delete(&organization).await?;
        }
        let deleted = plugin
            .store
            .delete_organization(&organization_id)
            .await?
            .ok_or_else(organization_not_found)?;
        if Self::active_organization_id(session) == Some(organization_id) {
            self.set_active_organization(session, None).await?;
        }
        if let Some(hooks) = &plugin.config.hooks {
            hooks.after_delete(&deleted, &session.user).await?;
        }
        Ok(deleted)
    }

    pub async fn list_organizations(
        &self,
        session: &SessionWithUser,
    ) -> Result<Vec<Organization>, AuthError> {
        self.organization_plugin()?
            .store
            .list_organizations(&session.user.id)
            .await
    }

    pub async fn get_organization(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        slug: Option<&str>,
    ) -> Result<Option<Organization>, AuthError> {
        let plugin = self.organization_plugin()?;
        let organization = match slug {
            Some(slug) => plugin.store.find_organization_by_slug(slug).await?,
            None => match organization_id.or_else(|| Self::active_organization_id(session)) {
                Some(id) => plugin.store.find_organization_by_id(&id).await?,
                None => return Ok(None),
            },
        };
        let Some(organization) = organization else {
            return Err(organization_not_found());
        };
        require_member(plugin, &organization.id, &session.user.id).await?;
        Ok(Some(organization))
    }

    pub async fn get_full_organization(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        slug: Option<&str>,
        members_limit: Option<usize>,
    ) -> Result<Option<FullOrganization>, AuthError> {
        let Some(organization) = self
            .get_organization(session, organization_id, slug)
            .await?
        else {
            return Ok(None);
        };
        let plugin = self.organization_plugin()?;
        let mut members = Vec::new();
        for member in plugin
            .store
            .list_members(&organization.id)
            .await?
            .into_iter()
            .take(members_limit.unwrap_or(plugin.config.membership_limit))
        {
            if let Some(user) = self.store.find_user_by_id(&member.user_id).await? {
                members.push(OrganizationMemberWithUser { member, user });
            }
        }
        let teams = if plugin.config.teams.enabled {
            Some(plugin.store.list_teams(&organization.id).await?)
        } else {
            None
        };
        let invitations = plugin.store.list_invitations(&organization.id).await?;
        Ok(Some(FullOrganization {
            organization,
            members,
            invitations,
            teams,
        }))
    }
}

type DefaultTeam = Option<(OrganizationTeam, OrganizationTeamMember)>;

async fn prepare_creation(
    plugin: &crate::OrganizationPlugin,
    session: &SessionWithUser,
    input: NewOrganization,
) -> Result<(Organization, OrganizationMember, DefaultTeam), AuthError> {
    let now = Utc::now();
    let mut organization = Organization {
        id: String::new(),
        name: input.name,
        slug: input.slug,
        logo: input.logo,
        metadata: input.metadata,
        created_at: now,
    };
    if let Some(hooks) = &plugin.config.hooks {
        organization = hooks.before_create(organization, &session.user).await?;
    }
    let mut member = OrganizationMember {
        id: String::new(),
        organization_id: organization.id.clone(),
        user_id: session.user.id.clone(),
        role: plugin.config.creator_role.clone(),
        created_at: now,
    };
    if let Some(hooks) = &plugin.config.hooks {
        member = hooks
            .before_add_member(member, &session.user, &organization)
            .await?;
    }
    let mut team = (plugin.config.teams.enabled && plugin.config.teams.default_team_enabled)
        .then(|| default_team(&organization, session.user.id.clone(), now));
    if let (Some(hooks), Some((team, team_member))) = (&plugin.config.hooks, team.as_mut()) {
        *team = hooks
            .before_create_team(team.clone(), &session.user, &organization)
            .await?;
        team_member.team_id = team.id.clone();
    }
    Ok((organization, member, team))
}

fn default_team(
    organization: &Organization,
    user_id: String,
    now: chrono::DateTime<Utc>,
) -> (OrganizationTeam, OrganizationTeamMember) {
    let team = OrganizationTeam {
        id: String::new(),
        name: organization.name.clone(),
        organization_id: organization.id.clone(),
        created_at: now,
        updated_at: None,
    };
    let member = OrganizationTeamMember {
        id: String::new(),
        team_id: team.id.clone(),
        user_id,
        created_at: now,
    };
    (team, member)
}

async fn require_member(
    plugin: &crate::OrganizationPlugin,
    organization_id: &str,
    user_id: &str,
) -> Result<OrganizationMember, AuthError> {
    plugin
        .store
        .find_member(organization_id, user_id)
        .await?
        .ok_or_else(|| {
            bad_request(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                "User is not a member of the organization",
            )
        })
}

async fn require_permission(
    service: &AuthService,
    member: &OrganizationMember,
    resource: &str,
    action: &str,
    code: &'static str,
    message: &'static str,
) -> Result<(), AuthError> {
    let required = BTreeMap::from([(resource.to_owned(), vec![action.to_owned()])]);
    if service
        .organization_has_permission(member, &required, false)
        .await?
    {
        Ok(())
    } else {
        Err(forbidden(code, message))
    }
}

fn organization_not_found() -> AuthError {
    bad_request("ORGANIZATION_NOT_FOUND", "Organization not found")
}

fn bad_request(code: &'static str, message: &'static str) -> AuthError {
    OrganizationError::bad_request(code, message).into()
}

fn forbidden(code: &'static str, message: &'static str) -> AuthError {
    OrganizationError::forbidden(code, message).into()
}
