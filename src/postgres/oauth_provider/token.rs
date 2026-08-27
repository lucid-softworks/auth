use super::{
    super::{PostgresModel, rows::update_query, storage_error},
    PostgresOAuthProviderStore,
    rows::{self, AccessRow, RefreshRow},
};
use crate::{
    AuthError, DatabaseIdSupplier,
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

mod logout;
mod revocation;
mod write;

fn select_model(
    model: &PostgresModel<'_>,
    projection: String,
) -> Result<QueryBuilder<'static, sqlx::Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(projection)
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
        let projection = rows::access_projection(&model)?;
        let mut query = select_model(&model, projection)?;
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
        let projection = rows::refresh_projection(&model)?;
        let mut query = select_model(&model, projection)?;
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

    async fn issue_oauth_tokens(
        &self,
        refresh_id: &dyn DatabaseIdSupplier,
        access_id: &dyn DatabaseIdSupplier,
        mut issuance: OAuthTokenIssuance,
    ) -> Result<(), AuthError> {
        let refresh = self.model("oauthRefreshToken")?;
        let access = self.model("oauthAccessToken")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        write::reserve_issuance_token_values(
            &mut transaction,
            issuance
                .refresh_token
                .as_ref()
                .map(|token| (&refresh, token.token.as_str())),
            issuance
                .access_token
                .as_ref()
                .map(|token| (&access, token.token.as_str())),
        )
        .await?;
        if let Some(token) = &issuance.refresh_token {
            let stored =
                write::insert_refresh_token(&mut transaction, refresh_id, token, &refresh).await?;
            if let Some(access) = issuance.access_token.as_mut()
                && access.refresh_id.is_some()
            {
                access.refresh_id = Some(stored.id);
            }
        }
        if let Some(token) = &issuance.access_token {
            write::insert_access_token(&mut transaction, access_id, token, &access).await?;
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn rotate_oauth_refresh_token(
        &self,
        refresh_id: &dyn DatabaseIdSupplier,
        access_id: &dyn DatabaseIdSupplier,
        mut rotation: OAuthRefreshRotation,
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
        consume.push(" WHERE \"id\" = ");
        refresh
            .encode("id", json!(rotation.previous_refresh_id))?
            .push_bind(&mut consume);
        consume
            .push(" AND ")
            .push(refresh.quoted_column("revoked")?)
            .push(" IS NULL RETURNING ")
            .push(rows::refresh_projection(&refresh)?);
        let consumed = consume
            .build_query_as::<RefreshRow>()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?;
        if consumed.is_none() {
            let projection = rows::refresh_projection(&refresh)?;
            let mut previous = select_model(&refresh, projection)?;
            previous.push(" WHERE \"id\" = ");
            refresh
                .encode("id", json!(rotation.previous_refresh_id))?
                .push_bind(&mut previous);
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
        write::reserve_issuance_token_values(
            &mut transaction,
            Some((&refresh, rotation.next_refresh_token.token.as_str())),
            rotation
                .access_token
                .as_ref()
                .map(|token| (&access, token.token.as_str())),
        )
        .await?;
        let next = write::insert_refresh_token(
            &mut transaction,
            refresh_id,
            &rotation.next_refresh_token,
            &refresh,
        )
        .await?;
        if let Some(token) = rotation.access_token.as_mut() {
            if token.refresh_id.is_some() {
                token.refresh_id = Some(next.id.clone());
            }
            write::insert_access_token(&mut transaction, access_id, token, &access).await?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(OAuthRefreshRotationOutcome::Rotated(next))
    }

    async fn store_oauth_refresh_rotation_replay(
        &self,
        refresh_id: &str,
        response: String,
    ) -> Result<bool, AuthError> {
        let model = self.model("oauthRefreshToken")?;
        let writes = model.encode_fields([("rotationReplayResponse", Value::String(response))])?;
        let mut query = update_query(&model, writes);
        query.push(" WHERE \"id\" = ");
        model.encode("id", json!(refresh_id))?.push_bind(&mut query);
        query
            .build()
            .execute(self.pool())
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
    }

    async fn delete_oauth_access_token(
        &self,
        id: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        let model = self.model("oauthAccessToken")?;
        let mut query = QueryBuilder::new("DELETE FROM ");
        query.push(model.quoted_table()).push(" WHERE \"id\" = ");
        model.encode("id", json!(id))?.push_bind(&mut query);
        query
            .push(" RETURNING ")
            .push(rows::access_projection(&model)?);
        query
            .build_query_as::<AccessRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(Into::into))
            .map_err(storage_error)
    }

    async fn revoke_oauth_refresh_token(
        &self,
        id: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let refresh = self.model("oauthRefreshToken")?;
        let access = self.model("oauthAccessToken")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let writes =
            refresh.encode_fields([("revoked", Value::String(revoked_at.to_rfc3339()))])?;
        let mut query = update_query(&refresh, writes);
        query.push(" WHERE \"id\" = ");
        refresh.encode("id", json!(id))?.push_bind(&mut query);
        query
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
            revocation::delete_where_id(&mut transaction, &access, "refreshId", id).await?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(revoked)
    }

    async fn revoke_oauth_refresh_family(
        &self,
        client_id: &str,
        user_id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let refresh = self.model("oauthRefreshToken")?;
        let access = self.model("oauthAccessToken")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let mut select = QueryBuilder::new("SELECT \"id\"::TEXT FROM ");
        select
            .push(refresh.quoted_table())
            .push(" WHERE ")
            .push(refresh.quoted_column("clientId")?)
            .push(" = ")
            .push_bind(client_id.to_owned())
            .push(" AND ")
            .push(refresh.quoted_column("userId")?)
            .push(" = ");
        refresh
            .encode("userId", json!(user_id))?
            .push_bind(&mut select);
        select.push(" FOR UPDATE");
        let refresh_ids = select
            .build_query_scalar::<String>()
            .fetch_all(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let access_tokens =
            revocation::delete_where_ids(&mut transaction, &access, "refreshId", &refresh_ids)
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
        session_id: &str,
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
        session_id: &str,
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
