use super::{codec, data::insert_id, eq, insert};
use crate::{
    AuthError, DatabaseIdSupplier, Organization, OrganizationCreateOutcome, OrganizationMember,
    OrganizationTeam, OrganizationTeamMember,
    mssql::{MssqlStore, query::execute, schema::MssqlSchema},
};
use crate::mssql::MssqlTransaction;

type DefaultTeam<'a> = (
    &'a mut OrganizationTeam,
    &'a dyn DatabaseIdSupplier,
    &'a mut OrganizationTeamMember,
    &'a dyn DatabaseIdSupplier,
);

pub(super) async fn create(
    store: &MssqlStore,
    organization: &mut Organization,
    organization_id: &dyn DatabaseIdSupplier,
    owner: &mut OrganizationMember,
    owner_id: &dyn DatabaseIdSupplier,
    default_team: Option<DefaultTeam<'_>>,
    organization_limit: Option<usize>,
) -> Result<OrganizationCreateOutcome, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.begin().await.map_err(super::storage)?;
    if let Some(outcome) = preflight(
        &mut transaction,
        schema,
        organization,
        owner,
        organization_limit,
    )
    .await?
    {
        transaction.rollback().await.map_err(super::storage)?;
        return outcome;
    }
    insert_organization_and_owner(
        store,
        &mut transaction,
        schema,
        organization,
        organization_id,
        owner,
        owner_id,
    )
    .await?;
    if let Some(team) = default_team {
        insert_default_team(store, &mut transaction, schema, &organization.id, team).await?;
    }
    transaction.commit().await.map_err(super::storage)?;
    Ok(OrganizationCreateOutcome::Created)
}

async fn preflight(
    transaction: &mut MssqlTransaction,
    schema: &MssqlSchema,
    organization: &Organization,
    owner: &OrganizationMember,
    limit: Option<usize>,
) -> Result<Option<Result<OrganizationCreateOutcome, AuthError>>, AuthError> {
    if execute::find_one(
        transaction,
        schema,
        "user",
        &[eq("id", &owner.user_id)],
        &[],
    )
    .await?
    .is_none()
    {
        return Ok(Some(Err(AuthError::NotFound)));
    }
    if execute::find_one(
        transaction,
        schema,
        "organization",
        &[eq("slug", &organization.slug)],
        &[],
    )
    .await?
    .is_some()
    {
        return Ok(Some(Ok(OrganizationCreateOutcome::SlugTaken)));
    }
    if let Some(limit) = limit
        && execute::count(
            transaction,
            schema,
            "member",
            &[eq("userId", &owner.user_id)],
        )
        .await?
            >= limit as u64
    {
        return Ok(Some(Ok(OrganizationCreateOutcome::LimitReached)));
    }
    Ok(None)
}

async fn insert_organization_and_owner(
    store: &MssqlStore,
    transaction: &mut MssqlTransaction,
    schema: &MssqlSchema,
    organization: &mut Organization,
    organization_id: &dyn DatabaseIdSupplier,
    owner: &mut OrganizationMember,
    owner_id: &dyn DatabaseIdSupplier,
) -> Result<(), AuthError> {
    let mut record = codec::organization_record(store, organization)?;
    insert_id(&mut record, organization_id.prepare()?)?;
    *organization = codec::decode_organization(
        execute::insert_required(transaction, schema, "organization", record).await?,
    )?;
    owner.organization_id = organization.id.clone();
    *owner = codec::decode(
        "member",
        insert(
            store,
            transaction,
            schema,
            "member",
            owner,
            owner_id.prepare()?,
        )
        .await?,
    )?;
    Ok(())
}

async fn insert_default_team(
    store: &MssqlStore,
    transaction: &mut MssqlTransaction,
    schema: &MssqlSchema,
    organization_id: &str,
    (team, team_id, team_member, team_member_id): DefaultTeam<'_>,
) -> Result<(), AuthError> {
    team.organization_id = organization_id.into();
    let mut team_record =
        super::super::codec::create_record(store, "team", team, &team_id.prepare()?)?;
    if schema.model("team")?.has_field("memberCount") {
        team_record.insert("memberCount".into(), serde_json::json!(0));
    }
    *team = codec::decode(
        "team",
        execute::insert_required(transaction, schema, "team", team_record).await?,
    )?;
    team_member.team_id = team.id.clone();
    let mut member_record = codec::team_member_record(store, team_member)?;
    insert_id(&mut member_record, team_member_id.prepare()?)?;
    *team_member = codec::decode(
        "teamMember",
        execute::insert_required(transaction, schema, "teamMember", member_record).await?,
    )?;
    Ok(())
}
