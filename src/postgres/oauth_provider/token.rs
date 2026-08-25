use super::{
    super::storage_error,
    PostgresOAuthProviderStore,
    rows::{ACCESS_FIELDS, AccessRow, REFRESH_FIELDS, RefreshRow},
};
use crate::{
    AuthError,
    oauth_provider::{
        OAuthProviderAccessToken, OAuthProviderRefreshToken, OAuthProviderTokenStore,
        OAuthRefreshRotation, OAuthRefreshRotationOutcome, OAuthSessionLogoutPlan,
        OAuthTokenIssuance, OAuthTokenRevocationCount,
        schema::{OAuthProviderModel, ResolvedModel},
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

mod logout;

async fn insert_refresh_token(
    connection: &mut PgConnection,
    token: &OAuthProviderRefreshToken,
    model: &ResolvedModel,
) -> Result<OAuthProviderRefreshToken, AuthError> {
    sqlx::query_as::<_, RefreshRow>(&format!(
        "INSERT INTO {} ({}) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) \
         RETURNING {}",
        model.table(),
        model.columns(REFRESH_FIELDS),
        model.projection(REFRESH_FIELDS)
    ))
    .bind(token.id)
    .bind(&token.token)
    .bind(&token.client_id)
    .bind(token.session_id)
    .bind(token.user_id)
    .bind(&token.reference_id)
    .bind(&token.authorization_code_id)
    .bind(&token.resources)
    .bind(&token.requested_user_info_claims)
    .bind(token.expires_at)
    .bind(token.created_at)
    .bind(token.revoked)
    .bind(token.rotated_at)
    .bind(&token.rotation_replay_response)
    .bind(token.rotation_replay_expires_at)
    .bind(token.auth_time)
    .bind(&token.confirmation)
    .bind(&token.scopes)
    .fetch_one(connection)
    .await
    .map(Into::into)
    .map_err(storage_error)
}

async fn insert_access_token(
    connection: &mut PgConnection,
    token: &OAuthProviderAccessToken,
    model: &ResolvedModel,
) -> Result<OAuthProviderAccessToken, AuthError> {
    sqlx::query_as::<_, AccessRow>(&format!(
        "INSERT INTO {} ({}) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
         RETURNING {}",
        model.table(),
        model.columns(ACCESS_FIELDS),
        model.projection(ACCESS_FIELDS)
    ))
    .bind(token.id)
    .bind(&token.token)
    .bind(&token.client_id)
    .bind(token.session_id)
    .bind(token.user_id)
    .bind(&token.reference_id)
    .bind(&token.authorization_code_id)
    .bind(&token.resources)
    .bind(&token.requested_user_info_claims)
    .bind(token.refresh_id)
    .bind(token.expires_at)
    .bind(token.created_at)
    .bind(token.revoked)
    .bind(&token.confirmation)
    .bind(&token.scopes)
    .fetch_one(connection)
    .await
    .map(Into::into)
    .map_err(storage_error)
}

#[async_trait]
impl OAuthProviderTokenStore for PostgresOAuthProviderStore {
    async fn find_oauth_access_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::AccessToken);
        sqlx::query_as::<_, AccessRow>(&format!(
            "SELECT {} FROM {} WHERE {}=$1",
            model.projection(ACCESS_FIELDS),
            model.table(),
            model.column("token")
        ))
        .bind(token)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn find_oauth_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::RefreshToken);
        sqlx::query_as::<_, RefreshRow>(&format!(
            "SELECT {} FROM {} WHERE {}=$1",
            model.projection(REFRESH_FIELDS),
            model.table(),
            model.column("token")
        ))
        .bind(token)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn issue_oauth_tokens(&self, issuance: OAuthTokenIssuance) -> Result<(), AuthError> {
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        if let Some(refresh) = &issuance.refresh_token {
            insert_refresh_token(
                &mut transaction,
                refresh,
                self.schema.model(OAuthProviderModel::RefreshToken),
            )
            .await?;
        }
        if let Some(access) = &issuance.access_token {
            insert_access_token(
                &mut transaction,
                access,
                self.schema.model(OAuthProviderModel::AccessToken),
            )
            .await?;
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn rotate_oauth_refresh_token(
        &self,
        rotation: OAuthRefreshRotation,
    ) -> Result<OAuthRefreshRotationOutcome, AuthError> {
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let refresh = self.schema.model(OAuthProviderModel::RefreshToken);
        let consumed = sqlx::query_as::<_, RefreshRow>(&format!(
            "UPDATE {} SET {}=$2, {}=$2, {}=$3 WHERE \"id\"=$1 AND {} IS NULL RETURNING {}",
            refresh.table(),
            refresh.column("revoked"),
            refresh.column("rotatedAt"),
            refresh.column("rotationReplayExpiresAt"),
            refresh.column("revoked"),
            refresh.projection(REFRESH_FIELDS)
        ))
        .bind(rotation.previous_refresh_id)
        .bind(rotation.rotated_at)
        .bind(rotation.replay_expires_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;

        if consumed.is_none() {
            let previous = sqlx::query_as::<_, RefreshRow>(&format!(
                "SELECT {} FROM {} WHERE \"id\"=$1",
                refresh.projection(REFRESH_FIELDS),
                refresh.table()
            ))
            .bind(rotation.previous_refresh_id)
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
            insert_refresh_token(&mut transaction, &rotation.next_refresh_token, refresh).await?;
        if let Some(access) = &rotation.access_token {
            insert_access_token(
                &mut transaction,
                access,
                self.schema.model(OAuthProviderModel::AccessToken),
            )
            .await?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(OAuthRefreshRotationOutcome::Rotated(next))
    }

    async fn store_oauth_refresh_rotation_replay(
        &self,
        refresh_id: Uuid,
        response: String,
    ) -> Result<bool, AuthError> {
        let model = self.schema.model(OAuthProviderModel::RefreshToken);
        sqlx::query(&format!(
            "UPDATE {} SET {}=$2 WHERE \"id\"=$1",
            model.table(),
            model.column("rotationReplayResponse")
        ))
        .bind(refresh_id)
        .bind(response)
        .execute(self.pool())
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(storage_error)
    }

    async fn delete_oauth_access_token(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::AccessToken);
        sqlx::query_as::<_, AccessRow>(&format!(
            "DELETE FROM {} WHERE \"id\"=$1 RETURNING {}",
            model.table(),
            model.projection(ACCESS_FIELDS)
        ))
        .bind(id)
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
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let refresh = self.schema.model(OAuthProviderModel::RefreshToken);
        let revoked = sqlx::query(&format!(
            "UPDATE {} SET {}=$2 WHERE \"id\"=$1 AND {} IS NULL",
            refresh.table(),
            refresh.column("revoked"),
            refresh.column("revoked")
        ))
        .bind(id)
        .bind(revoked_at)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?
        .rows_affected()
            == 1;
        if revoked {
            let access = self.schema.model(OAuthProviderModel::AccessToken);
            sqlx::query(&format!(
                "DELETE FROM {} WHERE {}=$1",
                access.table(),
                access.column("refreshId")
            ))
            .bind(id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(revoked)
    }

    async fn revoke_oauth_refresh_family(
        &self,
        client_id: &str,
        user_id: Uuid,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let refresh = self.schema.model(OAuthProviderModel::RefreshToken);
        let refresh_ids = sqlx::query_scalar::<_, Uuid>(&format!(
            "SELECT \"id\" FROM {} WHERE {}=$1 AND {}=$2 FOR UPDATE",
            refresh.table(),
            refresh.column("clientId"),
            refresh.column("userId")
        ))
        .bind(client_id)
        .bind(user_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage_error)?;
        let access = self.schema.model(OAuthProviderModel::AccessToken);
        let access_tokens = sqlx::query(&format!(
            "DELETE FROM {} WHERE {}=ANY($1::UUID[])",
            access.table(),
            access.column("refreshId")
        ))
        .bind(&refresh_ids)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?
        .rows_affected() as usize;
        let refresh_tokens = sqlx::query(&format!(
            "DELETE FROM {} WHERE \"id\"=ANY($1::UUID[])",
            refresh.table()
        ))
        .bind(&refresh_ids)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?
        .rows_affected() as usize;
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
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let access = self.schema.model(OAuthProviderModel::AccessToken);
        let access_tokens = sqlx::query(&format!(
            "DELETE FROM {} WHERE {}=$1",
            access.table(),
            access.column("authorizationCodeId")
        ))
        .bind(authorization_code_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?
        .rows_affected() as usize;
        let refresh = self.schema.model(OAuthProviderModel::RefreshToken);
        let refresh_tokens = sqlx::query(&format!(
            "DELETE FROM {} WHERE {}=$1",
            refresh.table(),
            refresh.column("authorizationCodeId")
        ))
        .bind(authorization_code_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?
        .rows_affected() as usize;
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
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let access = self.schema.model(OAuthProviderModel::AccessToken);
        let access_tokens = sqlx::query(&format!(
            "UPDATE {} SET {}=$2 WHERE {}=$1 AND {} IS NULL",
            access.table(),
            access.column("revoked"),
            access.column("sessionId"),
            access.column("revoked")
        ))
        .bind(session_id)
        .bind(revoked_at)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?
        .rows_affected() as usize;
        let refresh = self.schema.model(OAuthProviderModel::RefreshToken);
        let refresh_tokens = sqlx::query(&format!(
            "UPDATE {} SET {}=$2 WHERE {}=$1 AND {} IS NULL \
             AND (NOT $3 OR NOT ('offline_access'=ANY({})))",
            refresh.table(),
            refresh.column("revoked"),
            refresh.column("sessionId"),
            refresh.column("revoked"),
            refresh.column("scopes")
        ))
        .bind(session_id)
        .bind(revoked_at)
        .bind(preserve_offline_access)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?
        .rows_affected() as usize;
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
