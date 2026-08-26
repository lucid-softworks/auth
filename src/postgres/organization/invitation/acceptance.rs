use super::super::storage_error;
use super::query::{
    count_by_organization, find, insert_member, member_exists, update_status, uuid_value,
};
use crate::{
    AuthError, OrganizationInvitation, OrganizationInvitationStatus,
    OrganizationInvitationWriteOutcome, OrganizationMember, OrganizationTeamMember,
    postgres::PostgresModel,
};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

pub(super) struct InvitationAcceptanceContext<'model, 'schema> {
    pub(super) pool: &'model sqlx::PgPool,
    pub(super) organization: &'model PostgresModel<'schema>,
    pub(super) invitation: &'model PostgresModel<'schema>,
    pub(super) member: &'model PostgresModel<'schema>,
    pub(super) teams: Option<(
        &'model PostgresModel<'schema>,
        &'model PostgresModel<'schema>,
    )>,
    pub(super) invitation_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) now: DateTime<Utc>,
    pub(super) membership_limit: usize,
}

pub(super) async fn accept_invitation_transaction(
    context: InvitationAcceptanceContext<'_, '_>,
) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
    let InvitationAcceptanceContext {
        pool,
        organization,
        invitation: invitation_model,
        member: member_model,
        teams: team_models,
        invitation_id,
        user_id,
        now,
        membership_limit,
    } = context;
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let Some(invitation) = find(
        &mut *transaction,
        invitation_model,
        [("id", uuid_value(invitation_id))],
        true,
    )
    .await?
    else {
        return Ok(OrganizationInvitationWriteOutcome::NotFound);
    };
    if invitation.status != OrganizationInvitationStatus::Pending {
        return Ok(OrganizationInvitationWriteOutcome::NotFound);
    }
    if invitation.expires_at <= now {
        return Ok(OrganizationInvitationWriteOutcome::Expired);
    }
    super::super::member::lock_organization(
        &mut transaction,
        organization,
        invitation.organization_id,
    )
    .await?;
    if member_exists(
        &mut transaction,
        member_model,
        invitation.organization_id,
        user_id,
    )
    .await?
    {
        return Ok(OrganizationInvitationWriteOutcome::AlreadyMember);
    }
    if count_by_organization(&mut transaction, member_model, invitation.organization_id).await?
        >= membership_limit as i64
    {
        return Ok(OrganizationInvitationWriteOutcome::LimitReached);
    }
    write_acceptance(
        &mut transaction,
        invitation_model,
        member_model,
        team_models,
        invitation,
        user_id,
        now,
    )
    .await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(OrganizationInvitationWriteOutcome::Written)
}

async fn write_acceptance(
    transaction: &mut Transaction<'_, Postgres>,
    invitation_model: &PostgresModel<'_>,
    member_model: &PostgresModel<'_>,
    team_models: Option<(&PostgresModel<'_>, &PostgresModel<'_>)>,
    invitation: OrganizationInvitation,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    insert_member(
        transaction,
        member_model,
        &OrganizationMember {
            id: Uuid::new_v4(),
            organization_id: invitation.organization_id,
            user_id,
            role: invitation.role.clone(),
            created_at: now,
        },
    )
    .await?;
    if let Some((team, team_member)) = team_models {
        for team_id in invitation
            .team_id
            .as_deref()
            .into_iter()
            .flat_map(|ids| ids.split(','))
            .filter_map(|id| Uuid::parse_str(id).ok())
        {
            insert_team_member_if_owned(
                transaction,
                team,
                team_member,
                OrganizationTeamMember {
                    id: Uuid::new_v4(),
                    team_id,
                    user_id,
                    created_at: now,
                },
                invitation.organization_id,
            )
            .await?;
        }
    }
    update_status(
        transaction,
        invitation_model,
        invitation.id,
        OrganizationInvitationStatus::Accepted,
    )
    .await
}

async fn insert_team_member_if_owned(
    transaction: &mut Transaction<'_, Postgres>,
    team: &PostgresModel<'_>,
    team_member: &PostgresModel<'_>,
    member: OrganizationTeamMember,
    organization_id: Uuid,
) -> Result<(), AuthError> {
    let mut exists = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    exists.push(team.quoted_table()).push(" WHERE \"id\" = ");
    team.encode("id", uuid_value(member.team_id))?
        .push_bind(&mut exists);
    exists
        .push(" AND ")
        .push(team.quoted_column("organizationId")?)
        .push(" = ");
    team.encode("organizationId", uuid_value(organization_id))?
        .push_bind(&mut exists);
    exists.push(")");
    if !exists
        .build_query_scalar::<bool>()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?
    {
        return Ok(());
    }
    let mut query = crate::postgres::rows::insert_query_prefix(
        team_member,
        super::super::rows::team_member_writes(team_member, &member)?,
    );
    query
        .push(" ON CONFLICT (")
        .push(team_member.quoted_column("membershipKey")?)
        .push(") DO NOTHING");
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}
