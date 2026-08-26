use super::{rows, storage_error};
use crate::{
    AuthError, OrganizationMember, OrganizationMemberStore, OrganizationMemberWriteOutcome,
    postgres::PostgresStore,
};
use async_trait::async_trait;
use uuid::Uuid;

mod query;

pub(super) use query::lock_organization;
use query::*;

#[async_trait]
impl OrganizationMemberStore for PostgresStore {
    async fn raw_insert_member(
        &self,
        member: OrganizationMember,
    ) -> Result<OrganizationMember, AuthError> {
        let model = self.physical_model("member")?;
        let mut connection = self.pool.acquire().await.map_err(storage_error)?;
        insert_member(&mut *connection, &model, &member).await?;
        Ok(member)
    }

    async fn find_member_by_id(&self, id: Uuid) -> Result<Option<OrganizationMember>, AuthError> {
        let model = self.physical_model("member")?;
        find(&self.pool, &model, [("id", uuid_value(id))], false).await
    }

    async fn find_member(
        &self,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<Option<OrganizationMember>, AuthError> {
        let model = self.physical_model("member")?;
        find(
            &self.pool,
            &model,
            [
                ("organizationId", uuid_value(organization_id)),
                ("userId", serde_json::json!(user_id)),
            ],
            false,
        )
        .await
    }

    async fn list_members(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationMember>, AuthError> {
        let model = self.physical_model("member")?;
        let mut query = list_query(&model, organization_id)?;
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .iter()
            .map(|row| rows::decode_member(&model, row))
            .collect()
    }

    async fn add_member(
        &self,
        member: OrganizationMember,
        membership_limit: usize,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let organization_model = self.physical_model("organization")?;
        let member_model = self.physical_model("member")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(
            &mut transaction,
            &organization_model,
            member.organization_id,
        )
        .await?;
        if member_exists(
            &mut transaction,
            &member_model,
            member.organization_id,
            &member.user_id,
        )
        .await?
        {
            return Ok(OrganizationMemberWriteOutcome::AlreadyMember);
        }
        if member_count(&mut transaction, &member_model, member.organization_id).await?
            >= membership_limit as i64
        {
            return Ok(OrganizationMemberWriteOutcome::LimitReached);
        }
        insert_member(&mut *transaction, &member_model, &member).await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn update_member_role(
        &self,
        member_id: Uuid,
        role: String,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let organization_model = self.physical_model("organization")?;
        let member_model = self.physical_model("member")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let Some(current) = find(
            &mut *transaction,
            &member_model,
            [("id", uuid_value(member_id))],
            true,
        )
        .await?
        else {
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        lock_organization(
            &mut transaction,
            &organization_model,
            current.organization_id,
        )
        .await?;
        if has_role(&current.role, creator_role)
            && !has_role(&role, creator_role)
            && owner_count(
                &mut transaction,
                &member_model,
                current.organization_id,
                creator_role,
            )
            .await?
                <= 1
        {
            return Ok(OrganizationMemberWriteOutcome::LastOwner);
        }
        update_role(&mut transaction, &member_model, member_id, role).await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn remove_member(
        &self,
        member_id: Uuid,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let organization_model = self.physical_model("organization")?;
        let member_model = self.physical_model("member")?;
        let team_model = self.physical_model_if_present("team")?;
        let team_member_model = self.physical_model_if_present("teamMember")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let Some(current) = find(
            &mut *transaction,
            &member_model,
            [("id", uuid_value(member_id))],
            true,
        )
        .await?
        else {
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        lock_organization(
            &mut transaction,
            &organization_model,
            current.organization_id,
        )
        .await?;
        if has_role(&current.role, creator_role)
            && owner_count(
                &mut transaction,
                &member_model,
                current.organization_id,
                creator_role,
            )
            .await?
                <= 1
        {
            return Ok(OrganizationMemberWriteOutcome::LastOwner);
        }
        delete_member(&mut transaction, &member_model, member_id).await?;
        match (&team_model, &team_member_model) {
            (Some(team), Some(team_member)) => {
                delete_team_members(
                    &mut transaction,
                    team,
                    team_member,
                    current.organization_id,
                    &current.user_id,
                )
                .await?;
            }
            (None, None) => {}
            _ => return Err(incomplete_team_schema()),
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }
}
