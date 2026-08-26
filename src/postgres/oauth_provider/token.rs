use super::{
    super::{PostgresModel, rows::update_query, storage_error},
    PostgresOAuthProviderStore,
    rows::{ACCESS_FIELDS, AccessRow, REFRESH_FIELDS, RefreshRow},
};
use crate::{
    AuthError,
    oauth_provider::{
        OAuthProviderAccessToken, OAuthProviderRefreshToken, OAuthProviderTokenStore,
        OAuthRefreshRotation, OAuthRefreshRotationOutcome, OAuthSessionLogoutPlan,
        OAuthTokenIssuance, OAuthTokenRevocationCount,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::QueryBuilder;
use uuid::Uuid;

mod logout;
mod revocation;
mod write;

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
impl OAuthProviderTokenStore for PostgresOAuthProviderStore {
    async fn find_oauth_access_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        let model = self.model("oauthAccessToken")?;
        let mut query = select_model(&model, ACCESS_FIELDS)?;
        query
            .push(" WHERE ")
            .push(model.quoted_column("token")?)
            .push(" = ")
            .push_bind(token.to_owned());
        query
            .build_query_as::<AccessRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(Into::into))
            .map_err(storage_error)
    }

    async fn find_oauth_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
        let model = self.model("oauthRefreshToken")?;
        let mut query = select_model(&model, REFRESH_FIELDS)?;
        query
            .push(" WHERE ")
            .push(model.quoted_column("token")?)
            .push(" = ")
            .push_bind(token.to_owned());
        query
            .build_query_as::<RefreshRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(Into::into))
            .map_err(storage_error)
    }

    async fn issue_oauth_tokens(&self, issuance: OAuthTokenIssuance) -> Result<(), AuthError> {
        let refresh = self.model("oauthRefreshToken")?;
        let access = self.model("oauthAccessToken")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        if let Some(token) = &issuance.refresh_token {
            write::insert_refresh_token(&mut transaction, token, &refresh).await?;
        }
        if let Some(token) = &issuance.access_token {
            write::insert_access_token(&mut transaction, token, &access).await?;
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn rotate_oauth_refresh_token(
        &self,
        rotation: OAuthRefreshRotation,
    ) -> Result<OAuthRefreshRotationOutcome, AuthError> {
        let refresh = self.model("oauthRefreshToken")?;
        let access = self.model("oauthAccessToken")?;
        let writes = refresh.encode_fields([
            ("revoked", json!(rotation.rotated_at.to_rfc3339())),
            ("rotatedAt", json!(rotation.rotated_at.to_rfc3339())),
            (
                "rotationReplayExpiresAt",
                rotation
                    .replay_expires_at
                    .map_or(Value::Null, |value| json!(value.to_rfc3339())),
            ),
        ])?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let mut consume = update_query(&refresh, writes);
        consume
            .push(" WHERE \"id\" = ")
            .push_bind(rotation.previous_refresh_id)
            .push(" AND ")
            .push(refresh.quoted_column("revoked")?)
            .push(" IS NULL RETURNING ")
            .push(refresh.projection_as(REFRESH_FIELDS)?);
        let consumed = consume
            .build_query_as::<RefreshRow>()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?;
        if consumed.is_none() {
            let mut previous = select_model(&refresh, REFRESH_FIELDS)?;
            previous
                .push(" WHERE \"id\" = ")
                .push_bind(rotation.previous_refresh_id);
            let previous = previous
                .build_query_as::<RefreshRow>()
                .fetch_optional(&mut *transaction)
                .await
                .map_err(storage_error)?;
            return Ok(
                previous.map_or(OAuthRefreshRotationOutcome::NotFound, |token| {
                    OAuthRefreshRotationOutcome::AlreadyConsumed(token.into())
                }),
            );
        }
        let next =
            write::insert_refresh_token(&mut transaction, &rotation.next_refresh_token, &refresh)
                .await?;
        if let Some(token) = &rotation.access_token {
            write::insert_access_token(&mut transaction, token, &access).await?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(OAuthRefreshRotationOutcome::Rotated(next))
    }

    async fn store_oauth_refresh_rotation_replay(
        &self,
        refresh_id: Uuid,
        response: String,
    ) -> Result<bool, AuthError> {
        let model = self.model("oauthRefreshToken")?;
        let writes = model.encode_fields([("rotationReplayResponse", Value::String(response))])?;
        let mut query = update_query(&model, writes);
        query.push(" WHERE \"id\" = ").push_bind(refresh_id);
        query
            .build()
            .execute(self.pool())
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
    }

    async fn delete_oauth_access_token(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        let model = self.model("oauthAccessToken")?;
        let mut query = QueryBuilder::new("DELETE FROM ");
        query
            .push(model.quoted_table())
            .push(" WHERE \"id\" = ")
            .push_bind(id)
            .push(" RETURNING ")
            .push(model.projection_as(ACCESS_FIELDS)?);
        query
            .build_query_as::<AccessRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(Into::into))
            .map_err(storage_error)
    }

    async fn revoke_oauth_refresh_token(
        &self,
        id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let refresh = self.model("oauthRefreshToken")?;
        let access = self.model("oauthAccessToken")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let writes =
            refresh.encode_fields([("revoked", Value::String(revoked_at.to_rfc3339()))])?;
        let mut query = update_query(&refresh, writes);
        query
            .push(" WHERE \"id\" = ")
            .push_bind(id)
            .push(" AND ")
            .push(refresh.quoted_column("revoked")?)
            .push(" IS NULL");
        let revoked = query
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?
            .rows_affected()
            == 1;
        if revoked {
            revocation::delete_where_uuid(&mut transaction, &access, "refreshId", id).await?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(revoked)
    }

    async fn revoke_oauth_refresh_family(
        &self,
        client_id: &str,
        user_id: Uuid,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let refresh = self.model("oauthRefreshToken")?;
        let access = self.model("oauthAccessToken")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let mut select = QueryBuilder::new("SELECT \"id\" FROM ");
        select
            .push(refresh.quoted_table())
            .push(" WHERE ")
            .push(refresh.quoted_column("clientId")?)
            .push(" = ")
            .push_bind(client_id.to_owned())
            .push(" AND ")
            .push(refresh.quoted_column("userId")?)
            .push(" = ")
            .push_bind(user_id)
            .push(" FOR UPDATE");
        let refresh_ids = select
            .build_query_scalar::<Uuid>()
            .fetch_all(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let access_tokens = revocation::delete_where_ids(
            &mut transaction,
            &access,
            access.quoted_column("refreshId")?,
            &refresh_ids,
        )
        .await?;
        let refresh_tokens =
            revocation::delete_where_ids(&mut transaction, &refresh, "\"id\"", &refresh_ids)
                .await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OAuthTokenRevocationCount {
            access_tokens,
            refresh_tokens,
        })
    }

    async fn revoke_oauth_tokens_for_authorization_code(
        &self,
        authorization_code_id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let access = self.model("oauthAccessToken")?;
        let refresh = self.model("oauthRefreshToken")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let access_tokens = revocation::delete_where_text(
            &mut transaction,
            &access,
            "authorizationCodeId",
            authorization_code_id,
        )
        .await?;
        let refresh_tokens = revocation::delete_where_text(
            &mut transaction,
            &refresh,
            "authorizationCodeId",
            authorization_code_id,
        )
        .await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OAuthTokenRevocationCount {
            access_tokens,
            refresh_tokens,
        })
    }

    async fn revoke_oauth_tokens_for_session(
        &self,
        session_id: Uuid,
        revoked_at: DateTime<Utc>,
        preserve_offline_access: bool,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let access = self.model("oauthAccessToken")?;
        let refresh = self.model("oauthRefreshToken")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let access_tokens = revocation::revoke_for_session(
            &mut transaction,
            &access,
            session_id,
            revoked_at,
            false,
        )
        .await?;
        let refresh_tokens = revocation::revoke_for_session(
            &mut transaction,
            &refresh,
            session_id,
            revoked_at,
            preserve_offline_access,
        )
        .await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OAuthTokenRevocationCount {
            access_tokens,
            refresh_tokens,
        })
    }

    async fn prepare_oauth_session_logout(
        &self,
        session_id: Uuid,
    ) -> Result<OAuthSessionLogoutPlan, AuthError> {
        logout::prepare(self, session_id).await
    }

    async fn apply_oauth_session_logout(
        &self,
        plan: &OAuthSessionLogoutPlan,
        revoked_at: DateTime<Utc>,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        logout::apply(self, plan, revoked_at).await
    }
}
