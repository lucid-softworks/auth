use super::{codec, eq};
use crate::{
    AuthError, DatabaseIdSupplier, OrganizationTeam, OrganizationTeamMember, OrganizationTeamStore,
    OrganizationTeamWriteOutcome,
    mongodb::{MongoFindOptions, MongoStore, query::execute},
};
use async_trait::async_trait;
use serde_json::{Map, Value};

#[async_trait]
impl OrganizationTeamStore for MongoStore {
    async fn create_team(
        &self,
        team: &mut OrganizationTeam,
        id: &dyn DatabaseIdSupplier,
        maximum_teams: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        if execute::find_one(
            &mut transaction,
            schema,
            "organization",
            &[eq("id", &team.organization_id)],
            &[],
        )
        .await?
        .is_none()
        {
            return Err(AuthError::NotFound);
        }
        let organization = [eq("organizationId", &team.organization_id)];
        if execute::find_one(
            &mut transaction,
            schema,
            "team",
            &[
                eq("organizationId", &team.organization_id),
                eq("name", &team.name),
            ],
            &[],
        )
        .await?
        .is_some()
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationTeamWriteOutcome::AlreadyExists);
        }
        if let Some(limit) = maximum_teams
            && execute::count(&mut transaction, schema, "team", &organization).await?
                >= limit as u64
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationTeamWriteOutcome::LimitReached);
        }
        let mut record = super::super::codec::create_record(self, "team", team, &id.prepare()?)?;
        if schema.model("team")?.has_field("memberCount") {
            record.insert("memberCount".into(), serde_json::json!(0));
        }
        *team = codec::decode(
            "team",
            execute::insert_required(&mut transaction, schema, "team", record).await?,
        )?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn find_team(&self, id: &str) -> Result<Option<OrganizationTeam>, AuthError> {
        find(self, id).await
    }

    async fn list_teams(&self, organization_id: &str) -> Result<Vec<OrganizationTeam>, AuthError> {
        self.find_records(
            "team",
            &[eq("organizationId", organization_id)],
            &MongoFindOptions::default(),
        )
        .await?
        .into_iter()
        .map(|record| codec::decode("team", record))
        .collect()
    }

    async fn update_team(
        &self,
        team: OrganizationTeam,
    ) -> Result<Option<OrganizationTeam>, AuthError> {
        let values = super::super::codec::update_record(self, "team", &team)?;
        self.update_record("team", &[eq("id", &team.id)], values)
            .await?
            .map(|record| codec::decode("team", record))
            .transpose()
    }

    async fn remove_team(
        &self,
        id: &str,
        allow_removing_all: bool,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let Some(team) = find_tx(&mut transaction, schema, id).await? else {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationTeamWriteOutcome::NotFound);
        };
        if !allow_removing_all
            && execute::count(
                &mut transaction,
                schema,
                "team",
                &[eq("organizationId", &team.organization_id)],
            )
            .await?
                <= 1
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationTeamWriteOutcome::LastTeam);
        }
        execute::delete_many(&mut transaction, schema, "teamMember", &[eq("teamId", id)]).await?;
        if schema.model("invitation")?.has_field("teamId") {
            execute::update_many(
                &mut transaction,
                schema,
                "invitation",
                &[
                    eq("organizationId", &team.organization_id),
                    eq("teamId", id),
                ],
                Map::from_iter([("teamId".into(), Value::Null)]),
            )
            .await?;
        }
        execute::delete_many(&mut transaction, schema, "team", &[eq("id", id)]).await?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn add_team_member(
        &self,
        member: &mut OrganizationTeamMember,
        id: &dyn DatabaseIdSupplier,
        maximum_members: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        if execute::find_one(
            &mut transaction,
            schema,
            "team",
            &[eq("id", &member.team_id)],
            &[],
        )
        .await?
        .is_none()
        {
            return Err(AuthError::NotFound);
        }
        let filters = [eq("teamId", &member.team_id)];
        if execute::find_one(
            &mut transaction,
            schema,
            "teamMember",
            &[eq("teamId", &member.team_id), eq("userId", &member.user_id)],
            &[],
        )
        .await?
        .is_some()
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationTeamWriteOutcome::AlreadyExists);
        }
        if let Some(limit) = maximum_members
            && execute::count(&mut transaction, schema, "teamMember", &filters).await?
                >= limit as u64
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OrganizationTeamWriteOutcome::LimitReached);
        }
        let mut record = codec::team_member_record(self, member)?;
        insert_id(&mut record, id.prepare()?)?;
        *member = codec::decode(
            "teamMember",
            execute::insert_required(&mut transaction, schema, "teamMember", record).await?,
        )?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn remove_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        Ok(
            if self
                .delete_records(
                    "teamMember",
                    &[eq("teamId", team_id), eq("userId", user_id)],
                )
                .await?
                == 0
            {
                OrganizationTeamWriteOutcome::NotFound
            } else {
                OrganizationTeamWriteOutcome::Written
            },
        )
    }

    async fn list_team_members(
        &self,
        team_id: &str,
    ) -> Result<Vec<OrganizationTeamMember>, AuthError> {
        self.find_records(
            "teamMember",
            &[eq("teamId", team_id)],
            &MongoFindOptions::default(),
        )
        .await?
        .into_iter()
        .map(|record| codec::decode("teamMember", record))
        .collect()
    }

    async fn list_user_teams(&self, user_id: &str) -> Result<Vec<OrganizationTeam>, AuthError> {
        let members = self
            .find_records(
                "teamMember",
                &[eq("userId", user_id)],
                &MongoFindOptions::default(),
            )
            .await?;
        let mut teams = Vec::new();
        for member in members {
            let id = member
                .get("teamId")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AuthError::Storage("invalid MongoDB teamMember row: teamId".into())
                })?;
            if let Some(team) = find(self, id).await? {
                teams.push(team);
            }
        }
        Ok(teams)
    }
}

async fn find(store: &MongoStore, id: &str) -> Result<Option<OrganizationTeam>, AuthError> {
    store
        .find_record("team", &[eq("id", id)], &[])
        .await?
        .map(|record| codec::decode("team", record))
        .transpose()
}
async fn find_tx(
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &super::super::schema::MongoSchema,
    id: &str,
) -> Result<Option<OrganizationTeam>, AuthError> {
    execute::find_one(transaction, schema, "team", &[eq("id", id)], &[])
        .await?
        .map(|record| codec::decode("team", record))
        .transpose()
}
fn insert_id(
    record: &mut Map<String, Value>,
    id: crate::PreparedDatabaseId,
) -> Result<(), AuthError> {
    if let crate::PreparedDatabaseId::Value(value) = id {
        record.insert("id".into(), value.to_json()?);
    }
    Ok(())
}
