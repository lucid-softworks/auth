use super::{codec, eq, token_io};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthProviderAccessToken, OAuthProviderRefreshToken,
    OAuthProviderTokenStore, OAuthRefreshRotation, OAuthRefreshRotationOutcome,
    OAuthSessionLogoutPlan, OAuthTokenIssuance, OAuthTokenRevocationCount,
    mongodb::{MongoFilter, MongoFindOptions, MongoStore, query::execute},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl OAuthProviderTokenStore for MongoStore {
    async fn find_oauth_access_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        token_io::find_access(self, &[eq("token", token)]).await
    }
    async fn find_oauth_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
        token_io::find_refresh(self, &[eq("token", token)]).await
    }

    async fn issue_oauth_tokens(
        &self,
        refresh_id: &dyn DatabaseIdSupplier,
        access_id: &dyn DatabaseIdSupplier,
        issuance: OAuthTokenIssuance,
    ) -> Result<(), AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        token_io::validate(&mut transaction, schema, &issuance).await?;
        token_io::insert_issuance(
            self,
            &mut transaction,
            schema,
            refresh_id,
            access_id,
            issuance,
        )
        .await?;
        transaction.commit().await.map_err(super::storage)
    }

    async fn rotate_oauth_refresh_token(
        &self,
        refresh_id: &dyn DatabaseIdSupplier,
        access_id: &dyn DatabaseIdSupplier,
        mut rotation: OAuthRefreshRotation,
    ) -> Result<OAuthRefreshRotationOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let Some(previous_row) = execute::find_one(
            &mut transaction,
            schema,
            "oauthRefreshToken",
            &[eq("id", &rotation.previous_refresh_id)],
            &[],
        )
        .await?
        else {
            return Ok(OAuthRefreshRotationOutcome::NotFound);
        };
        let previous = codec::decode_refresh(previous_row)?;
        if previous.revoked.is_some() {
            return Ok(OAuthRefreshRotationOutcome::AlreadyConsumed(previous));
        }
        let issuance = OAuthTokenIssuance {
            access_token: rotation.access_token.take(),
            refresh_token: Some(rotation.next_refresh_token),
        };
        token_io::validate(&mut transaction, schema, &issuance).await?;
        execute::update_one(
            &mut transaction,
            schema,
            "oauthRefreshToken",
            &[
                eq("id", &rotation.previous_refresh_id),
                MongoFilter::equal("revoked", Value::Null),
            ],
            Map::from_iter([
                ("revoked".into(), json!(rotation.rotated_at)),
                ("rotatedAt".into(), json!(rotation.rotated_at)),
                (
                    "rotationReplayExpiresAt".into(),
                    json!(rotation.replay_expires_at),
                ),
            ]),
        )
        .await?
        .ok_or_else(|| AuthError::Storage("OAuth refresh token changed during rotation".into()))?;
        rotation.next_refresh_token = token_io::insert_issuance(
            self,
            &mut transaction,
            schema,
            refresh_id,
            access_id,
            issuance,
        )
        .await?
        .expect("rotation includes a refresh token");
        transaction.commit().await.map_err(super::storage)?;
        Ok(OAuthRefreshRotationOutcome::Rotated(
            rotation.next_refresh_token,
        ))
    }

    async fn store_oauth_refresh_rotation_replay(
        &self,
        refresh_id: &str,
        response: String,
    ) -> Result<bool, AuthError> {
        Ok(self
            .update_record(
                "oauthRefreshToken",
                &[eq("id", refresh_id)],
                Map::from_iter([("rotationReplayResponse".into(), json!(response))]),
            )
            .await?
            .is_some())
    }

    async fn delete_oauth_access_token(
        &self,
        id: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        self.consume_record("oauthAccessToken", &[eq("id", id)])
            .await?
            .map(codec::decode_access)
            .transpose()
    }

    async fn revoke_oauth_refresh_token(
        &self,
        id: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let updated = execute::update_one(
            &mut transaction,
            schema,
            "oauthRefreshToken",
            &[eq("id", id), MongoFilter::equal("revoked", Value::Null)],
            Map::from_iter([("revoked".into(), json!(revoked_at))]),
        )
        .await?
        .is_some();
        if updated {
            execute::delete_many(
                &mut transaction,
                schema,
                "oauthAccessToken",
                &[eq("refreshId", id)],
            )
            .await?;
        }
        transaction.commit().await.map_err(super::storage)?;
        Ok(updated)
    }

    async fn revoke_oauth_refresh_family(
        &self,
        client_id: &str,
        user_id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        token_io::delete_family(self, &[eq("clientId", client_id), eq("userId", user_id)]).await
    }

    async fn revoke_oauth_tokens_for_authorization_code(
        &self,
        id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let access = execute::delete_many(
            &mut transaction,
            schema,
            "oauthAccessToken",
            &[eq("authorizationCodeId", id)],
        )
        .await?;
        let refresh = execute::delete_many(
            &mut transaction,
            schema,
            "oauthRefreshToken",
            &[eq("authorizationCodeId", id)],
        )
        .await?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(token_io::counts(access, refresh))
    }

    async fn revoke_oauth_tokens_for_session(
        &self,
        session_id: &str,
        revoked_at: DateTime<Utc>,
        preserve_offline_access: bool,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let plan = self.prepare_oauth_session_logout(session_id).await?;
        let mut plan = plan;
        if !preserve_offline_access {
            plan.refresh_token_ids = self
                .find_records(
                    "oauthRefreshToken",
                    &[
                        eq("sessionId", session_id),
                        MongoFilter::equal("revoked", Value::Null),
                    ],
                    &MongoFindOptions::default(),
                )
                .await?
                .into_iter()
                .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
                .collect();
        }
        self.apply_oauth_session_logout(&plan, revoked_at).await
    }

    async fn prepare_oauth_session_logout(
        &self,
        session_id: &str,
    ) -> Result<OAuthSessionLogoutPlan, AuthError> {
        let access = token_io::list_access(self, &[eq("sessionId", session_id)]).await?;
        let refresh = token_io::list_refresh(self, &[eq("sessionId", session_id)]).await?;
        let mut client_ids = access
            .iter()
            .map(|token| token.client_id.clone())
            .chain(refresh.iter().map(|token| token.client_id.clone()))
            .collect::<Vec<_>>();
        client_ids.sort();
        client_ids.dedup();
        Ok(OAuthSessionLogoutPlan {
            client_ids,
            access_token_ids: access
                .into_iter()
                .filter(|token| token.revoked.is_none())
                .map(|token| token.id)
                .collect(),
            refresh_token_ids: refresh
                .into_iter()
                .filter(|token| {
                    token.revoked.is_none()
                        && !token.scopes.iter().any(|scope| scope == "offline_access")
                })
                .map(|token| token.id)
                .collect(),
        })
    }

    async fn apply_oauth_session_logout(
        &self,
        plan: &OAuthSessionLogoutPlan,
        revoked_at: DateTime<Utc>,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.begin().await?;
        let mut counts = OAuthTokenRevocationCount::default();
        for id in &plan.access_token_ids {
            if execute::update_one(
                &mut transaction,
                schema,
                "oauthAccessToken",
                &[eq("id", id), MongoFilter::equal("revoked", Value::Null)],
                Map::from_iter([("revoked".into(), json!(revoked_at))]),
            )
            .await?
            .is_some()
            {
                counts.access_tokens += 1;
            }
        }
        for id in &plan.refresh_token_ids {
            if execute::update_one(
                &mut transaction,
                schema,
                "oauthRefreshToken",
                &[eq("id", id), MongoFilter::equal("revoked", Value::Null)],
                Map::from_iter([("revoked".into(), json!(revoked_at))]),
            )
            .await?
            .is_some()
            {
                counts.refresh_tokens += 1;
            }
        }
        transaction.commit().await.map_err(super::storage)?;
        Ok(counts)
    }
}
