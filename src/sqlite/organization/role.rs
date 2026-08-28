use super::{codec, eq};
use crate::{
    AuthError, DatabaseIdSupplier, OrganizationRole, OrganizationRoleStore,
    sqlite::{SqliteFindOptions, SqliteStore},
};
use async_trait::async_trait;

#[async_trait]
impl OrganizationRoleStore for SqliteStore {
    async fn create_role(
        &self,
        role: &mut OrganizationRole,
        id: &dyn DatabaseIdSupplier,
        maximum_roles: Option<usize>,
    ) -> Result<bool, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
        let filters = [eq("organizationId", &role.organization_id)];
        if let Some(limit) = maximum_roles
            && super::super::query::execute::count(
                &mut transaction,
                schema,
                "organizationRole",
                &filters,
            )
            .await?
                >= limit as u64
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(false);
        }
        let prepared = id.prepare()?;
        let mut record = codec::role_record(self, role)?;
        if let crate::PreparedDatabaseId::Value(value) = prepared {
            record.insert("id".into(), value.to_json()?);
        }
        let inserted = super::super::query::execute::insert(
            &mut transaction,
            schema,
            "organizationRole",
            record,
        )
        .await;
        let inserted = match inserted {
            Ok(record) => record,
            Err(AuthError::Storage(message)) if message.contains("UNIQUE constraint failed") => {
                transaction.rollback().await.map_err(super::storage)?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        *role = codec::decode_role(inserted)?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(true)
    }

    async fn find_role(&self, id: &str) -> Result<Option<OrganizationRole>, AuthError> {
        find(self, &[eq("id", id)]).await
    }

    async fn find_role_by_name(
        &self,
        organization_id: &str,
        role: &str,
    ) -> Result<Option<OrganizationRole>, AuthError> {
        find(
            self,
            &[eq("organizationId", organization_id), eq("role", role)],
        )
        .await
    }

    async fn list_roles(&self, organization_id: &str) -> Result<Vec<OrganizationRole>, AuthError> {
        self.find_records(
            "organizationRole",
            &[eq("organizationId", organization_id)],
            &SqliteFindOptions::default(),
        )
        .await?
        .into_iter()
        .map(codec::decode_role)
        .collect()
    }

    async fn update_role(
        &self,
        role: OrganizationRole,
    ) -> Result<Option<OrganizationRole>, AuthError> {
        let values = codec::role_record(self, &role)?;
        self.update_record("organizationRole", &[eq("id", &role.id)], values)
            .await?
            .map(codec::decode_role)
            .transpose()
    }

    async fn delete_role(&self, id: &str) -> Result<bool, AuthError> {
        Ok(self
            .delete_records("organizationRole", &[eq("id", id)])
            .await?
            == 1)
    }
}

async fn find(
    store: &SqliteStore,
    filters: &[super::super::SqliteFilter],
) -> Result<Option<OrganizationRole>, AuthError> {
    store
        .find_record("organizationRole", filters, &[])
        .await?
        .map(codec::decode_role)
        .transpose()
}
