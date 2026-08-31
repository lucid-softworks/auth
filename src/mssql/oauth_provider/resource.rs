use super::{codec, eq, record};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthClientResourceLinkOutcome, OAuthProviderClientResource,
    OAuthProviderResource, OAuthProviderResourceStore,
    mssql::{MssqlFindOptions, MssqlSort, MssqlSortDirection, MssqlStore, query::execute},
};
use async_trait::async_trait;

#[async_trait]
impl OAuthProviderResourceStore for MssqlStore {
    async fn find_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        find_resource(self, identifier).await
    }

    async fn list_oauth_resources(&self) -> Result<Vec<OAuthProviderResource>, AuthError> {
        self.find_records("oauthResource", &[], &sorted("identifier"))
            .await?
            .into_iter()
            .map(|row| codec::decode("oauthResource", row))
            .collect()
    }

    async fn create_oauth_resource(
        &self,
        id: &dyn DatabaseIdSupplier,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        if find_resource(self, &resource.identifier).await?.is_some() {
            return Ok(None);
        }
        let values = record(self, "oauthResource", &resource, Some(id.prepare()?), [])?;
        match self.insert_required_record("oauthResource", values).await {
            Ok(row) => codec::decode("oauthResource", row).map(Some),
            Err(error) if crate::mssql::error::is_unique_violation(&error) => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn update_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let mut values = record(self, "oauthResource", &resource, None, [])?;
        values.remove("identifier");
        self.update_record(
            "oauthResource",
            &[
                eq("id", &resource.id),
                eq("identifier", &resource.identifier),
            ],
            values,
        )
        .await?
        .map(|row| codec::decode("oauthResource", row))
        .transpose()
    }

    async fn delete_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await.map_err(super::storage)?;
        execute::delete_many(
            &mut transaction,
            schema,
            "oauthClientResource",
            &[eq("resourceId", identifier)],
        )
        .await?;
        let deleted = execute::consume_one(
            &mut transaction,
            schema,
            "oauthResource",
            &[eq("identifier", identifier)],
        )
        .await?
        .map(|row| codec::decode("oauthResource", row))
        .transpose()?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(deleted)
    }

    async fn list_oauth_client_resources(
        &self,
        client_id: &str,
    ) -> Result<Vec<OAuthProviderClientResource>, AuthError> {
        self.find_records(
            "oauthClientResource",
            &[eq("clientId", client_id)],
            &sorted("resourceId"),
        )
        .await?
        .into_iter()
        .map(|row| codec::decode("oauthClientResource", row))
        .collect()
    }

    async fn link_oauth_client_resource(
        &self,
        id: &dyn DatabaseIdSupplier,
        link: OAuthProviderClientResource,
    ) -> Result<OAuthClientResourceLinkOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await.map_err(super::storage)?;
        if execute::find_one(
            &mut transaction,
            schema,
            "oauthClient",
            &[eq("clientId", &link.client_id)],
            &[],
        )
        .await?
        .is_none()
        {
            return Ok(OAuthClientResourceLinkOutcome::ClientNotFound);
        }
        if execute::find_one(
            &mut transaction,
            schema,
            "oauthResource",
            &[eq("identifier", &link.resource_id)],
            &[],
        )
        .await?
        .is_none()
        {
            return Ok(OAuthClientResourceLinkOutcome::ResourceNotFound);
        }
        let filters = [
            eq("clientId", &link.client_id),
            eq("resourceId", &link.resource_id),
        ];
        if let Some(existing) = execute::find_one(
            &mut transaction,
            schema,
            "oauthClientResource",
            &filters,
            &[],
        )
        .await?
        {
            return codec::decode("oauthClientResource", existing)
                .map(OAuthClientResourceLinkOutcome::AlreadyLinked);
        }
        let values = record(self, "oauthClientResource", &link, Some(id.prepare()?), [])?;
        let inserted =
            execute::insert_required(&mut transaction, schema, "oauthClientResource", values).await;
        let outcome = match inserted {
            Ok(row) => {
                OAuthClientResourceLinkOutcome::Linked(codec::decode("oauthClientResource", row)?)
            }
            Err(error) if crate::mssql::error::is_unique_violation(&error) => {
                let existing = execute::find_one(
                    &mut transaction,
                    schema,
                    "oauthClientResource",
                    &filters,
                    &[],
                )
                .await?
                .ok_or_else(|| {
                    AuthError::Storage("OAuth client-resource conflict disappeared".into())
                })?;
                OAuthClientResourceLinkOutcome::AlreadyLinked(codec::decode(
                    "oauthClientResource",
                    existing,
                )?)
            }
            Err(error) => return Err(error),
        };
        transaction.commit().await.map_err(super::storage)?;
        Ok(outcome)
    }

    async fn unlink_oauth_client_resource(
        &self,
        client_id: &str,
        resource_id: &str,
    ) -> Result<Option<OAuthProviderClientResource>, AuthError> {
        self.consume_record(
            "oauthClientResource",
            &[eq("clientId", client_id), eq("resourceId", resource_id)],
        )
        .await?
        .map(|row| codec::decode("oauthClientResource", row))
        .transpose()
    }
}

async fn find_resource(
    store: &MssqlStore,
    identifier: &str,
) -> Result<Option<OAuthProviderResource>, AuthError> {
    store
        .find_record("oauthResource", &[eq("identifier", identifier)], &[])
        .await?
        .map(|row| codec::decode("oauthResource", row))
        .transpose()
}
fn sorted(field: &str) -> MssqlFindOptions {
    MssqlFindOptions {
        sort: Some(MssqlSort {
            field: field.into(),
            direction: MssqlSortDirection::Ascending,
        }),
        ..MssqlFindOptions::default()
    }
}
