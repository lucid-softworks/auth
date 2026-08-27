use super::{rows, storage_error};
use crate::{
    AuthError, OrganizationMember, OrganizationMemberStore, OrganizationMemberWriteOutcome,
    postgres::PostgresStore,
};
use async_trait::async_trait;
use serde_json::json;

mod query;

pub(super) use query::lock_organization;
use query::*;

#[async_trait]
impl OrganizationMemberStore for PostgresStore {
    async fn raw_insert_member(
        &self,
        member: OrganizationMember,
        id: &dyn crate::DatabaseIdSupplier,
    ) -> Result<OrganizationMember, AuthError> {
        let model = self.physical_model("member")?;
        let mut connection = self.pool.acquire().await.map_err(storage_error)?;
        let id = id.prepare()?;
        insert_member(&mut *connection, &model, &member, &id).await
    }

    async fn find_member_by_id(&self, id: &str) -> Result<Option<OrganizationMember>, AuthError> {
        let model = self.physical_model("member")?;
        find(&self.pool, &model, [("id", json!(id))], false).await
    }

    async fn find_member(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> Result<Option<OrganizationMember>, AuthError> {
        let model = self.physical_model("member")?;
        find(
            &self.pool,
            &model,
            [
                ("organizationId", json!(organization_id)),
                ("userId", serde_json::json!(user_id)),
            ],
            false,
        )
        .await
    }

    async fn list_members(
        &self,
        organization_id: &str,
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
        member: &mut OrganizationMember,
        id: &dyn crate::DatabaseIdSupplier,
        membership_limit: usize,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let organization_model = self.physical_model("organization")?;
        let member_model = self.physical_model("member")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(
            &mut transaction,
            &organization_model,
            &member.organization_id,
        )
        .await?;
        if member_exists(
            &mut transaction,
            &member_model,
            &member.organization_id,
            &member.user_id,
        )
        .await?
        {
            return Ok(OrganizationMemberWriteOutcome::AlreadyMember);
        }
        if member_count(&mut transaction, &member_model, &member.organization_id).await?
            >= membership_limit as i64
        {
            return Ok(OrganizationMemberWriteOutcome::LimitReached);
        }
        let prepared = id.prepare()?;
        *member = insert_member(&mut *transaction, &member_model, member, &prepared).await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn update_member_role(
        &self,
        member_id: &str,
        role: String,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let organization_model = self.physical_model("organization")?;
        let member_model = self.physical_model("member")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let Some(current) = find(
            &mut *transaction,
            &member_model,
            [("id", json!(member_id))],
            true,
        )
        .await?
        else {
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        lock_organization(
            &mut transaction,
            &organization_model,
            &current.organization_id,
        )
        .await?;
        if has_role(&current.role, creator_role)
            && !has_role(&role, creator_role)
            && owner_count(
                &mut transaction,
                &member_model,
                &current.organization_id,
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
        member_id: &str,
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
            [("id", json!(member_id))],
            true,
        )
        .await?
        else {
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        lock_organization(
            &mut transaction,
            &organization_model,
            &current.organization_id,
        )
        .await?;
        if has_role(&current.role, creator_role)
            && owner_count(
                &mut transaction,
                &member_model,
                &current.organization_id,
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
                    &current.organization_id,
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
