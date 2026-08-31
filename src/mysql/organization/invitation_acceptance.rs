use super::{codec, eq, insert, invitation::insert_id};
use crate::{
    AuthError, DatabaseIdSupplier, OrganizationInvitation, OrganizationInvitationStatus,
    OrganizationInvitationWriteOutcome, OrganizationMember, OrganizationTeamMember,
    mysql::{MySqlStore, query::execute, schema::MySqlSchema},
};
use chrono::{DateTime, Utc};
use serde_json::{Map, json};
use sqlx::{MySql, Transaction};

pub(super) async fn accept(
    store: &MySqlStore,
    invitation_id: &str,
    user_id: &str,
    now: DateTime<Utc>,
    membership_limit: usize,
    member_id: &dyn DatabaseIdSupplier,
    team_member_id: &dyn DatabaseIdSupplier,
) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(super::storage)?;
    let Some(invitation) = load_invitation(&mut transaction, schema, invitation_id).await? else {
        return rollback(transaction, OrganizationInvitationWriteOutcome::NotFound).await;
    };
    if invitation.status != OrganizationInvitationStatus::Pending {
        return rollback(transaction, OrganizationInvitationWriteOutcome::NotFound).await;
    }
    if invitation.expires_at <= now {
        return rollback(transaction, OrganizationInvitationWriteOutcome::Expired).await;
    }
    if let Some(outcome) = membership_conflict(
        &mut transaction,
        schema,
        &invitation.organization_id,
        user_id,
        membership_limit,
    )
    .await?
    {
        return rollback(transaction, outcome).await;
    }
    insert_member(
        store,
        &mut transaction,
        schema,
        &invitation,
        user_id,
        now,
        member_id,
    )
    .await?;
    attach_teams(
        store,
        &mut transaction,
        schema,
        &invitation,
        user_id,
        now,
        team_member_id,
    )
    .await?;
    mark_accepted(&mut transaction, schema, invitation_id).await?;
    transaction.commit().await.map_err(super::storage)?;
    Ok(OrganizationInvitationWriteOutcome::Written)
}

async fn load_invitation(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    id: &str,
) -> Result<Option<OrganizationInvitation>, AuthError> {
    execute::find_one(transaction, schema, "invitation", &[eq("id", id)], &[])
        .await?
        .map(|record| codec::decode("invitation", record))
        .transpose()
}

async fn membership_conflict(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    organization_id: &str,
    user_id: &str,
    limit: usize,
) -> Result<Option<OrganizationInvitationWriteOutcome>, AuthError> {
    if execute::find_one(
        transaction,
        schema,
        "member",
        &[eq("organizationId", organization_id), eq("userId", user_id)],
        &[],
    )
    .await?
    .is_some()
    {
        return Ok(Some(OrganizationInvitationWriteOutcome::AlreadyMember));
    }
    let count = execute::count(
        transaction,
        schema,
        "member",
        &[eq("organizationId", organization_id)],
    )
    .await?;
    Ok((count >= limit as u64).then_some(OrganizationInvitationWriteOutcome::LimitReached))
}

async fn insert_member(
    store: &MySqlStore,
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    invitation: &OrganizationInvitation,
    user_id: &str,
    now: DateTime<Utc>,
    id: &dyn DatabaseIdSupplier,
) -> Result<(), AuthError> {
    let member = OrganizationMember {
        id: String::new(),
        organization_id: invitation.organization_id.clone(),
        user_id: user_id.into(),
        role: invitation.role.clone(),
        created_at: now,
    };
    insert(store, transaction, schema, "member", &member, id.prepare()?).await?;
    Ok(())
}

async fn attach_teams(
    store: &MySqlStore,
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    invitation: &OrganizationInvitation,
    user_id: &str,
    now: DateTime<Utc>,
    id: &dyn DatabaseIdSupplier,
) -> Result<(), AuthError> {
    let Some(team_ids) = invitation.team_id.as_deref() else {
        return Ok(());
    };
    if !schema.has_model("team") || !schema.has_model("teamMember") {
        return Err(AuthError::InvalidConfiguration(
            "organization team schema is incomplete".into(),
        ));
    }
    for team_id in team_ids.split(',') {
        if !team_exists(transaction, schema, team_id, &invitation.organization_id).await?
            || team_member_exists(transaction, schema, team_id, user_id).await?
        {
            continue;
        }
        let member = OrganizationTeamMember {
            id: String::new(),
            team_id: team_id.into(),
            user_id: user_id.into(),
            created_at: now,
        };
        let mut record = codec::team_member_record(store, &member)?;
        insert_id(&mut record, id.prepare()?)?;
        execute::insert_required(transaction, schema, "teamMember", record).await?;
    }
    Ok(())
}

async fn team_exists(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    team_id: &str,
    organization_id: &str,
) -> Result<bool, AuthError> {
    Ok(execute::find_one(
        transaction,
        schema,
        "team",
        &[eq("id", team_id), eq("organizationId", organization_id)],
        &[],
    )
    .await?
    .is_some())
}

async fn team_member_exists(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    team_id: &str,
    user_id: &str,
) -> Result<bool, AuthError> {
    Ok(execute::find_one(
        transaction,
        schema,
        "teamMember",
        &[eq("teamId", team_id), eq("userId", user_id)],
        &[],
    )
    .await?
    .is_some())
}

async fn mark_accepted(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    id: &str,
) -> Result<(), AuthError> {
    execute::update_one(
        transaction,
        schema,
        "invitation",
        &[eq("id", id)],
        Map::from_iter([("status".into(), json!("accepted"))]),
    )
    .await?;
    Ok(())
}

async fn rollback(
    transaction: Transaction<'_, MySql>,
    outcome: OrganizationInvitationWriteOutcome,
) -> Result<OrganizationInvitationWriteOutcome, AuthError> {
    transaction.rollback().await.map_err(super::storage)?;
    Ok(outcome)
}
