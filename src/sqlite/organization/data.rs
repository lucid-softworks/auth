use super::{codec, create, eq};
use crate::{
    AuthError, DatabaseIdSupplier, Organization, OrganizationCreateOutcome, OrganizationDataStore,
    OrganizationMember, OrganizationTeam, OrganizationTeamMember,
    sqlite::{SqliteFindOptions, SqliteStore, query::execute},
};
use async_trait::async_trait;
use serde_json::{Map, Value};

#[async_trait]
impl OrganizationDataStore for SqliteStore {
    async fn raw_insert_organization(
        &self,
        organization: Organization,
        id: &dyn DatabaseIdSupplier,
    ) -> Result<Organization, AuthError> {
        let mut record = codec::organization_record(self, &organization)?;
        insert_id(&mut record, id.prepare()?)?;
        codec::decode_organization(self.insert_record("organization", record).await?)
    }

    async fn raw_delete_organization(&self, id: &str) -> Result<(), AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
        for model in ["member", "invitation"] {
            execute::delete_many(&mut transaction, schema, model, &[eq("organizationId", id)])
                .await?;
        }
        if schema.has_model("team") && schema.has_model("teamMember") {
            let teams = execute::find_many(
                &mut transaction,
                schema,
                "team",
                &[eq("organizationId", id)],
                &SqliteFindOptions::default(),
            )
            .await?;
            for team in teams {
                let team_id = team
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| AuthError::Storage("invalid SQLite team row: id".into()))?;
                execute::delete_many(
                    &mut transaction,
                    schema,
                    "teamMember",
                    &[eq("teamId", team_id)],
                )
                .await?;
            }
            execute::delete_many(
                &mut transaction,
                schema,
                "team",
                &[eq("organizationId", id)],
            )
            .await?;
        } else if schema.has_model("team") != schema.has_model("teamMember") {
            return Err(AuthError::InvalidConfiguration(
                "organization team schema is incomplete".into(),
            ));
        }
        if schema.has_model("organizationRole") {
            execute::delete_many(
                &mut transaction,
                schema,
                "organizationRole",
                &[eq("organizationId", id)],
            )
            .await?;
        }
        execute::delete_many(&mut transaction, schema, "organization", &[eq("id", id)]).await?;
        transaction.commit().await.map_err(super::storage)
    }

    async fn create_organization(
        &self,
        organization: &mut Organization,
        organization_id: &dyn DatabaseIdSupplier,
        owner: &mut OrganizationMember,
        owner_id: &dyn DatabaseIdSupplier,
        default_team: Option<(
            &mut OrganizationTeam,
            &dyn DatabaseIdSupplier,
            &mut OrganizationTeamMember,
            &dyn DatabaseIdSupplier,
        )>,
        organization_limit: Option<usize>,
    ) -> Result<OrganizationCreateOutcome, AuthError> {
        create::create(
            self,
            organization,
            organization_id,
            owner,
            owner_id,
            default_team,
            organization_limit,
        )
        .await
    }

    async fn find_organization_by_id(&self, id: &str) -> Result<Option<Organization>, AuthError> {
        find(self, "id", id).await
    }
    async fn find_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, AuthError> {
        find(self, "slug", slug).await
    }

    async fn list_organizations(&self, user_id: &str) -> Result<Vec<Organization>, AuthError> {
        let members = self
            .find_records(
                "member",
                &[eq("userId", user_id)],
                &SqliteFindOptions::default(),
            )
            .await?;
        let mut organizations = Vec::with_capacity(members.len());
        for member in members {
            let organization_id = member
                .get("organizationId")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AuthError::Storage("invalid SQLite member row: organizationId".into())
                })?;
            if let Some(organization) = find(self, "id", organization_id).await? {
                organizations.push(organization);
            }
        }
        Ok(organizations)
    }

    async fn update_organization(
        &self,
        organization: Organization,
    ) -> Result<Option<Organization>, AuthError> {
        let mut values = codec::organization_record(self, &organization)?;
        values.remove("id");
        self.update_record("organization", &[eq("id", &organization.id)], values)
            .await?
            .map(codec::decode_organization)
            .transpose()
    }

    async fn delete_organization(&self, id: &str) -> Result<Option<Organization>, AuthError> {
        self.consume_record("organization", &[eq("id", id)])
            .await?
            .map(codec::decode_organization)
            .transpose()
    }
}

async fn find(
    store: &SqliteStore,
    field: &str,
    value: &str,
) -> Result<Option<Organization>, AuthError> {
    store
        .find_record("organization", &[eq(field, value)], &[])
        .await?
        .map(codec::decode_organization)
        .transpose()
}

pub(super) fn insert_id(
    record: &mut Map<String, Value>,
    id: crate::PreparedDatabaseId,
) -> Result<(), AuthError> {
    if let crate::PreparedDatabaseId::Value(value) = id {
        record.insert("id".into(), value.to_json()?);
    }
    Ok(())
}
