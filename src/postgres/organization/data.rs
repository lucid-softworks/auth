use super::{rows, storage_error};
use crate::{
    AuthError, Organization, OrganizationCreateOutcome, OrganizationDataStore, OrganizationMember,
    OrganizationTeam, OrganizationTeamMember, postgres::PostgresStore,
};
use async_trait::async_trait;
use serde_json::json;
use uuid::Uuid;

mod query;

use query::*;

#[async_trait]
impl OrganizationDataStore for PostgresStore {
    async fn raw_insert_organization(
        &self,
        organization: Organization,
    ) -> Result<Organization, AuthError> {
        let model = self.physical_model("organization")?;
        insert_organization(&self.pool, &model, &organization).await?;
        Ok(organization)
    }

    async fn raw_delete_organization(&self, id: Uuid) -> Result<(), AuthError> {
        let organization = self.physical_model("organization")?;
        let member = self.physical_model("member")?;
        let invitation = self.physical_model("invitation")?;
        let team = self.physical_model_if_present("team")?;
        let team_member = self.physical_model_if_present("teamMember")?;
        let role = self.physical_model_if_present("organizationRole")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        delete_by(&mut transaction, &member, "organizationId", id).await?;
        delete_by(&mut transaction, &invitation, "organizationId", id).await?;
        if let (Some(team), Some(team_member)) = (&team, &team_member) {
            delete_team_members_for_organization(&mut transaction, team, team_member, id).await?;
            delete_by(&mut transaction, team, "organizationId", id).await?;
        } else if team.is_some() != team_member.is_some() {
            return Err(incomplete_team_schema());
        }
        if let Some(role) = &role {
            delete_by(&mut transaction, role, "organizationId", id).await?;
        }
        delete_by(&mut transaction, &organization, "id", id).await?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn create_organization(
        &self,
        organization: Organization,
        owner: OrganizationMember,
        default_team: Option<(OrganizationTeam, OrganizationTeamMember)>,
        organization_limit: Option<usize>,
    ) -> Result<OrganizationCreateOutcome, AuthError> {
        let organization_model = self.physical_model("organization")?;
        let member_model = self.physical_model("member")?;
        let user_model = self.physical_model("user")?;
        let team_models = if default_team.is_some() {
            Some((
                self.physical_model("team")?,
                self.physical_model("teamMember")?,
            ))
        } else {
            None
        };
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        lock_user(&mut transaction, &user_model, &owner.user_id).await?;
        advisory_slug_lock(&mut transaction, &organization.slug).await?;
        if slug_exists(&mut transaction, &organization_model, &organization.slug).await? {
            return Ok(OrganizationCreateOutcome::SlugTaken);
        }
        if let Some(limit) = organization_limit {
            let count = count_by(&mut transaction, &member_model, "userId", &owner.user_id).await?;
            if count >= limit as i64 {
                return Ok(OrganizationCreateOutcome::LimitReached);
            }
        }
        insert_organization(&mut *transaction, &organization_model, &organization).await?;
        insert_member(&mut *transaction, &member_model, &owner).await?;
        if let (Some((team, member)), Some((team_model, team_member_model))) =
            (default_team, team_models)
        {
            insert_team(&mut *transaction, &team_model, &team).await?;
            insert_team_member(&mut *transaction, &team_member_model, &member).await?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationCreateOutcome::Created)
    }

    async fn find_organization_by_id(&self, id: Uuid) -> Result<Option<Organization>, AuthError> {
        let model = self.physical_model("organization")?;
        fetch_organization(&self.pool, &model, "id", uuid_value(id)).await
    }

    async fn find_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, AuthError> {
        let model = self.physical_model("organization")?;
        fetch_organization(&self.pool, &model, "slug", json!(slug)).await
    }

    async fn list_organizations(&self, user_id: &str) -> Result<Vec<Organization>, AuthError> {
        let organization = self.physical_model("organization")?;
        let member = self.physical_model("member")?;
        let mut query = list_query(&organization, &member, user_id)?;
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .iter()
            .map(|row| rows::decode_organization(&organization, row))
            .collect()
    }

    async fn update_organization(
        &self,
        organization: Organization,
    ) -> Result<Option<Organization>, AuthError> {
        let model = self.physical_model("organization")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        if !lock_organization_row(&mut transaction, &model, organization.id).await? {
            return Ok(None);
        }
        advisory_slug_lock(&mut transaction, &organization.slug).await?;
        let mut query = update_query(&model, &organization)?;
        let row = query
            .build()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        row.as_ref()
            .map(|row| rows::decode_organization(&model, row))
            .transpose()
    }

    async fn delete_organization(&self, id: Uuid) -> Result<Option<Organization>, AuthError> {
        let model = self.physical_model("organization")?;
        let mut query = delete_query(&model, id)?;
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| rows::decode_organization(&model, row))
            .transpose()
    }
}
