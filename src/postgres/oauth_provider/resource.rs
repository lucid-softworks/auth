use super::{
    super::{
        PostgresModel,
        rows::{insert_query_prefix, update_query},
        storage_error,
    },
    PostgresOAuthProviderStore,
    rows::{self, LINK_FIELDS, LinkRow, RESOURCE_FIELDS, ResourceRow},
};
use crate::{
    AuthError,
    oauth_provider::{
        OAuthClientResourceLinkOutcome, OAuthProviderClientResource, OAuthProviderResource,
        OAuthProviderResourceStore,
    },
};
use async_trait::async_trait;
use sqlx::QueryBuilder;

fn decode_resource(row: ResourceRow) -> OAuthProviderResource {
    row.into()
}

fn decode_link(row: LinkRow) -> OAuthProviderClientResource {
    row.into()
}

fn select_model(
    model: &PostgresModel<'_>,
    fields: &[(&str, &str)],
) -> Result<QueryBuilder<'static, sqlx::Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.projection_as(fields)?)
        .push(" FROM ")
        .push(model.quoted_table());
    Ok(query)
}

#[async_trait]
impl OAuthProviderResourceStore for PostgresOAuthProviderStore {
    async fn find_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let model = self.model("oauthResource")?;
        let mut query = select_model(&model, RESOURCE_FIELDS)?;
        query
            .push(" WHERE ")
            .push(model.quoted_column("identifier")?)
            .push(" = ")
            .push_bind(identifier.to_owned());
        query
            .build_query_as::<ResourceRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(decode_resource))
            .map_err(storage_error)
    }

    async fn list_oauth_resources(&self) -> Result<Vec<OAuthProviderResource>, AuthError> {
        let model = self.model("oauthResource")?;
        let mut query = select_model(&model, RESOURCE_FIELDS)?;
        query
            .push(" ORDER BY ")
            .push(model.quoted_column("identifier")?);
        query
            .build_query_as::<ResourceRow>()
            .fetch_all(self.pool())
            .await
            .map(|rows| rows.into_iter().map(decode_resource).collect())
            .map_err(storage_error)
    }

    async fn create_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let model = self.model("oauthResource")?;
        let writes = rows::writes(&model, &resource, [])?;
        let mut query = insert_query_prefix(&model, writes);
        query
            .push(" ON CONFLICT (")
            .push(model.quoted_column("identifier")?)
            .push(") DO NOTHING RETURNING ")
            .push(model.projection_as(RESOURCE_FIELDS)?);
        query
            .build_query_as::<ResourceRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(decode_resource))
            .map_err(storage_error)
    }

    async fn update_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let model = self.model("oauthResource")?;
        let writes = rows::writes(&model, &resource, [])?
            .into_iter()
            .filter(|write| !matches!(write.logical(), "id" | "identifier"))
            .collect();
        let mut query = update_query(&model, writes);
        query
            .push(" WHERE \"id\" = ")
            .push_bind(resource.id)
            .push(" AND ")
            .push(model.quoted_column("identifier")?)
            .push(" = ")
            .push_bind(resource.identifier)
            .push(" RETURNING ")
            .push(model.projection_as(RESOURCE_FIELDS)?);
        query
            .build_query_as::<ResourceRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(decode_resource))
            .map_err(storage_error)
    }

    async fn delete_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let model = self.model("oauthResource")?;
        let mut query = QueryBuilder::new("DELETE FROM ");
        query
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column("identifier")?)
            .push(" = ")
            .push_bind(identifier.to_owned())
            .push(" RETURNING ")
            .push(model.projection_as(RESOURCE_FIELDS)?);
        query
            .build_query_as::<ResourceRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(decode_resource))
            .map_err(storage_error)
    }

    async fn list_oauth_client_resources(
        &self,
        client_id: &str,
    ) -> Result<Vec<OAuthProviderClientResource>, AuthError> {
        let model = self.model("oauthClientResource")?;
        let mut query = select_model(&model, LINK_FIELDS)?;
        query
            .push(" WHERE ")
            .push(model.quoted_column("clientId")?)
            .push(" = ")
            .push_bind(client_id.to_owned())
            .push(" ORDER BY ")
            .push(model.quoted_column("resourceId")?);
        query
            .build_query_as::<LinkRow>()
            .fetch_all(self.pool())
            .await
            .map(|rows| rows.into_iter().map(decode_link).collect())
            .map_err(storage_error)
    }

    async fn link_oauth_client_resource(
        &self,
        link: OAuthProviderClientResource,
    ) -> Result<OAuthClientResourceLinkOutcome, AuthError> {
        let client = self.model("oauthClient")?;
        let resource = self.model("oauthResource")?;
        let model = self.model("oauthClientResource")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(serde_json::json!([&link.client_id, &link.resource_id]).to_string())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        if !record_exists(&mut transaction, &client, "clientId", &link.client_id).await? {
            return Ok(OAuthClientResourceLinkOutcome::ClientNotFound);
        }
        if !record_exists(&mut transaction, &resource, "identifier", &link.resource_id).await? {
            return Ok(OAuthClientResourceLinkOutcome::ResourceNotFound);
        }
        let writes = rows::writes(&model, &link, [])?;
        let mut insert = insert_query_prefix(&model, writes);
        insert
            .push(" ON CONFLICT (")
            .push(model.quoted_column("clientId")?)
            .push(", ")
            .push(model.quoted_column("resourceId")?)
            .push(") DO NOTHING RETURNING ")
            .push(model.projection_as(LINK_FIELDS)?);
        let inserted = insert
            .build_query_as::<LinkRow>()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let outcome = if let Some(inserted) = inserted {
            OAuthClientResourceLinkOutcome::Linked(decode_link(inserted))
        } else {
            let mut select = select_model(&model, LINK_FIELDS)?;
            select
                .push(" WHERE ")
                .push(model.quoted_column("clientId")?)
                .push(" = ")
                .push_bind(link.client_id)
                .push(" AND ")
                .push(model.quoted_column("resourceId")?)
                .push(" = ")
                .push_bind(link.resource_id);
            let existing = select
                .build_query_as::<LinkRow>()
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage_error)?;
            OAuthClientResourceLinkOutcome::AlreadyLinked(decode_link(existing))
        };
        transaction.commit().await.map_err(storage_error)?;
        Ok(outcome)
    }

    async fn unlink_oauth_client_resource(
        &self,
        client_id: &str,
        resource_id: &str,
    ) -> Result<Option<OAuthProviderClientResource>, AuthError> {
        let model = self.model("oauthClientResource")?;
        let mut query = QueryBuilder::new("DELETE FROM ");
        query
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column("clientId")?)
            .push(" = ")
            .push_bind(client_id.to_owned())
            .push(" AND ")
            .push(model.quoted_column("resourceId")?)
            .push(" = ")
            .push_bind(resource_id.to_owned())
            .push(" RETURNING ")
            .push(model.projection_as(LINK_FIELDS)?);
        query
            .build_query_as::<LinkRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(decode_link))
            .map_err(storage_error)
    }
}

async fn record_exists(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    logical: &str,
    value: &str,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT 1 FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(logical)?)
        .push(" = ")
        .push_bind(value.to_owned())
        .push(" FOR KEY SHARE");
    query
        .build_query_scalar::<i32>()
        .fetch_optional(&mut **transaction)
        .await
        .map(|row| row.is_some())
        .map_err(storage_error)
}
