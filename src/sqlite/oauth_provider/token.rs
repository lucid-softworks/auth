use super::{codec, eq, record};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthProviderAccessToken, OAuthProviderRefreshToken,
    OAuthProviderTokenStore, OAuthRefreshRotation, OAuthRefreshRotationOutcome,
    OAuthSessionLogoutPlan, OAuthTokenIssuance, OAuthTokenRevocationCount,
    sqlite::{SqliteFilter, SqliteFindOptions, SqliteStore, query::execute},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl OAuthProviderTokenStore for SqliteStore {
    async fn find_oauth_access_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        find_access(self, &[eq("token", token)]).await
    }
    async fn find_oauth_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
        find_refresh(self, &[eq("token", token)]).await
    }

    async fn issue_oauth_tokens(
        &self,
        refresh_id: &dyn DatabaseIdSupplier,
        access_id: &dyn DatabaseIdSupplier,
        issuance: OAuthTokenIssuance,
    ) -> Result<(), AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
        validate(&mut transaction, schema, &issuance).await?;
        insert_issuance(
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
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
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
        validate(&mut transaction, schema, &issuance).await?;
        execute::update_one(
            &mut transaction,
            schema,
            "oauthRefreshToken",
            &[
                eq("id", &rotation.previous_refresh_id),
                SqliteFilter::equal("revoked", Value::Null),
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
        rotation.next_refresh_token = insert_issuance(
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
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
        let updated = execute::update_one(
            &mut transaction,
            schema,
            "oauthRefreshToken",
            &[eq("id", id), SqliteFilter::equal("revoked", Value::Null)],
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
        delete_family(self, &[eq("clientId", client_id), eq("userId", user_id)]).await
    }

    async fn revoke_oauth_tokens_for_authorization_code(
        &self,
        id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
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
        Ok(counts(access, refresh))
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
                        SqliteFilter::equal("revoked", Value::Null),
                    ],
                    &SqliteFindOptions::default(),
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
        let access = list_access(self, &[eq("sessionId", session_id)]).await?;
        let refresh = list_refresh(self, &[eq("sessionId", session_id)]).await?;
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
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
        let mut counts = OAuthTokenRevocationCount::default();
        for id in &plan.access_token_ids {
            if execute::update_one(
                &mut transaction,
                schema,
                "oauthAccessToken",
                &[eq("id", id), SqliteFilter::equal("revoked", Value::Null)],
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
                &[eq("id", id), SqliteFilter::equal("revoked", Value::Null)],
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

async fn validate(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    schema: &super::super::schema::SqliteSchema,
    issuance: &OAuthTokenIssuance,
) -> Result<(), AuthError> {
    if let Some(refresh) = &issuance.refresh_token
        && execute::find_one(
            transaction,
            schema,
            "oauthRefreshToken",
            &[eq("token", &refresh.token)],
            &[],
        )
        .await?
        .is_some()
    {
        return Err(AuthError::Storage(
            "OAuth refresh token identifier already exists".into(),
        ));
    }
    if let Some(access) = &issuance.access_token {
        if execute::find_one(
            transaction,
            schema,
            "oauthAccessToken",
            &[eq("token", &access.token)],
            &[],
        )
        .await?
        .is_some()
        {
            return Err(AuthError::Storage(
                "OAuth access token identifier already exists".into(),
            ));
        }
        if let Some(refresh_id) = &access.refresh_id
            && issuance
                .refresh_token
                .as_ref()
                .is_none_or(|refresh| refresh.id != *refresh_id && !refresh_id.is_empty())
            && execute::find_one(
                transaction,
                schema,
                "oauthRefreshToken",
                &[eq("id", refresh_id)],
                &[],
            )
            .await?
            .is_none()
        {
            return Err(AuthError::Storage(
                "OAuth access token references an unknown refresh token".into(),
            ));
        }
    }
    Ok(())
}

async fn insert_issuance(
    store: &SqliteStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    schema: &super::super::schema::SqliteSchema,
    refresh_id: &dyn DatabaseIdSupplier,
    access_id: &dyn DatabaseIdSupplier,
    mut issuance: OAuthTokenIssuance,
) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
    let stored_refresh = if let Some(refresh) = issuance.refresh_token {
        let values = refresh_record(store, &refresh, refresh_id.prepare()?)?;
        Some(codec::decode_refresh(
            execute::insert(transaction, schema, "oauthRefreshToken", values).await?,
        )?)
    } else {
        None
    };
    if let Some(access) = issuance.access_token.as_mut()
        && access.refresh_id.is_some()
        && let Some(refresh) = &stored_refresh
    {
        access.refresh_id = Some(refresh.id.clone());
    }
    if let Some(access) = issuance.access_token {
        let values = access_record(store, &access, access_id.prepare()?)?;
        execute::insert(transaction, schema, "oauthAccessToken", values).await?;
    }
    Ok(stored_refresh)
}

async fn delete_family(
    store: &SqliteStore,
    filters: &[SqliteFilter],
) -> Result<OAuthTokenRevocationCount, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(super::storage)?;
    let refresh = execute::find_many(
        &mut transaction,
        schema,
        "oauthRefreshToken",
        filters,
        &SqliteFindOptions::default(),
    )
    .await?;
    let ids = refresh
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    let mut access = 0;
    for id in &ids {
        access += execute::delete_many(
            &mut transaction,
            schema,
            "oauthAccessToken",
            &[eq("refreshId", id)],
        )
        .await?;
    }
    let refresh_count =
        execute::delete_many(&mut transaction, schema, "oauthRefreshToken", filters).await?;
    transaction.commit().await.map_err(super::storage)?;
    Ok(counts(access, refresh_count))
}

fn refresh_record(
    store: &SqliteStore,
    value: &OAuthProviderRefreshToken,
    id: crate::PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    record(
        store,
        "oauthRefreshToken",
        value,
        Some(id),
        [
            ("token", json!(value.token)),
            (
                "rotationReplayResponse",
                json!(value.rotation_replay_response),
            ),
        ],
    )
}
fn access_record(
    store: &SqliteStore,
    value: &OAuthProviderAccessToken,
    id: crate::PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    record(
        store,
        "oauthAccessToken",
        value,
        Some(id),
        [("token", json!(value.token))],
    )
}
fn counts(access: u64, refresh: u64) -> OAuthTokenRevocationCount {
    OAuthTokenRevocationCount {
        access_tokens: usize::try_from(access).unwrap_or(usize::MAX),
        refresh_tokens: usize::try_from(refresh).unwrap_or(usize::MAX),
    }
}
async fn find_access(
    store: &SqliteStore,
    filters: &[SqliteFilter],
) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
    store
        .find_record("oauthAccessToken", filters, &[])
        .await?
        .map(codec::decode_access)
        .transpose()
}
async fn find_refresh(
    store: &SqliteStore,
    filters: &[SqliteFilter],
) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
    store
        .find_record("oauthRefreshToken", filters, &[])
        .await?
        .map(codec::decode_refresh)
        .transpose()
}
async fn list_access(
    store: &SqliteStore,
    filters: &[SqliteFilter],
) -> Result<Vec<OAuthProviderAccessToken>, AuthError> {
    store
        .find_records("oauthAccessToken", filters, &SqliteFindOptions::default())
        .await?
        .into_iter()
        .map(codec::decode_access)
        .collect()
}
async fn list_refresh(
    store: &SqliteStore,
    filters: &[SqliteFilter],
) -> Result<Vec<OAuthProviderRefreshToken>, AuthError> {
    store
        .find_records("oauthRefreshToken", filters, &SqliteFindOptions::default())
        .await?
        .into_iter()
        .map(codec::decode_refresh)
        .collect()
}
