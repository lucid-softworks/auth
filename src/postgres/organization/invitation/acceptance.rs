use super::super::storage_error;
use super::query::{count_by_organization, find, insert_member, member_exists, update_status};
use crate::{
    AuthError, OrganizationInvitation, OrganizationInvitationStatus,
    OrganizationInvitationWriteOutcome, OrganizationMember, OrganizationTeamMember,
    postgres::PostgresModel,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, Transaction};

pub(super) struct InvitationAcceptanceContext<'model, 'schema> {
    pub(super) pool: &'model sqlx::PgPool,
    pub(super) organization: &'model PostgresModel<'schema>,
    pub(super) invitation: &'model PostgresModel<'schema>,
    pub(super) member: &'model PostgresModel<'schema>,
    pub(super) teams: Option<(
        &'model PostgresModel<'schema>,
        &'model PostgresModel<'schema>,
    )>,
    pub(super) invitation_id: &'model str,
    pub(super) user_id: &'model str,
    pub(super) now: DateTime<Utc>,
    pub(super) membership_limit: usize,
    pub(super) member_id: &'model dyn crate::DatabaseIdSupplier,
    pub(super) team_member_id: &'model dyn crate::DatabaseIdSupplier,
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
        member_id,
        team_member_id,
    } = context;
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let Some(invitation) = find(
        &mut *transaction,
        invitation_model,
        [("id", json!(invitation_id))],
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
        &invitation.organization_id,
    )
    .await?;
    if member_exists(
        &mut transaction,
        member_model,
        &invitation.organization_id,
        user_id,
    )
    .await?
    {
        return Ok(OrganizationInvitationWriteOutcome::AlreadyMember);
    }
    if count_by_organization(&mut transaction, member_model, &invitation.organization_id).await?
        >= membership_limit as i64
    {
        return Ok(OrganizationInvitationWriteOutcome::LimitReached);
    }
    write_acceptance(
        &mut transaction,
        AcceptanceWriteContext {
            invitation_model,
            member_model,
            team_models,
            invitation,
            user_id,
            now,
            member_id,
            team_member_id,
        },
    )
    .await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(OrganizationInvitationWriteOutcome::Written)
}

struct AcceptanceWriteContext<'model, 'schema> {
    invitation_model: &'model PostgresModel<'schema>,
    member_model: &'model PostgresModel<'schema>,
    team_models: Option<(
        &'model PostgresModel<'schema>,
        &'model PostgresModel<'schema>,
    )>,
    invitation: OrganizationInvitation,
    user_id: &'model str,
    now: DateTime<Utc>,
    member_id: &'model dyn crate::DatabaseIdSupplier,
    team_member_id: &'model dyn crate::DatabaseIdSupplier,
}

async fn write_acceptance(
    transaction: &mut Transaction<'_, Postgres>,
    context: AcceptanceWriteContext<'_, '_>,
) -> Result<(), AuthError> {
    let AcceptanceWriteContext {
        invitation_model,
        member_model,
        team_models,
        invitation,
        user_id,
        now,
        member_id,
        team_member_id,
    } = context;
    let member = OrganizationMember {
        id: String::new(),
        organization_id: invitation.organization_id.clone(),
        user_id: user_id.to_owned(),
        role: invitation.role.clone(),
        created_at: now,
    };
    let prepared = member_id.prepare()?;
    let _member = insert_member(transaction, member_model, &member, &prepared).await?;
    if let Some((team, team_member)) = team_models {
        for team_id in invitation
            .team_id
            .as_deref()
            .into_iter()
            .flat_map(|ids| ids.split(','))
            .map(str::to_owned)
        {
            insert_team_member_if_owned(
                transaction,
                team,
                team_member,
                &mut OrganizationTeamMember {
                    id: String::new(),
                    team_id,
                    user_id: user_id.to_owned(),
                    created_at: now,
                },
                &invitation.organization_id,
                team_member_id,
            )
            .await?;
        }
    }
    update_status(
        transaction,
        invitation_model,
        &invitation.id,
        OrganizationInvitationStatus::Accepted,
    )
    .await
}

async fn insert_team_member_if_owned(
    transaction: &mut Transaction<'_, Postgres>,
    team: &PostgresModel<'_>,
    team_member: &PostgresModel<'_>,
    member: &mut OrganizationTeamMember,
    organization_id: &str,
    id: &dyn crate::DatabaseIdSupplier,
) -> Result<(), AuthError> {
    let mut exists = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    exists.push(team.quoted_table()).push(" WHERE \"id\" = ");
    team.encode("id", json!(member.team_id))?
        .push_bind(&mut exists);
    exists
        .push(" AND ")
        .push(team.quoted_column("organizationId")?)
        .push(" = ");
    team.encode("organizationId", json!(organization_id))?
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
    let mut duplicate = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    duplicate
        .push(team_member.quoted_table())
        .push(" WHERE ")
        .push(team_member.quoted_column("teamId")?)
        .push(" = ");
    team_member
        .encode("teamId", json!(member.team_id))?
        .push_bind(&mut duplicate);
    duplicate
        .push(" AND ")
        .push(team_member.quoted_column("userId")?)
        .push(" = ");
    team_member
        .encode("userId", json!(member.user_id))?
        .push_bind(&mut duplicate);
    duplicate.push(")");
    if duplicate
        .build_query_scalar::<bool>()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?
    {
        return Ok(());
    }
    let prepared = id.prepare()?;
    let mut query = crate::postgres::rows::insert_query(
        team_member,
        super::super::rows::team_member_writes(team_member, member, &prepared)?,
    );
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    *member = super::super::rows::decode_team_member(team_member, &row)?;
    Ok(())
}
