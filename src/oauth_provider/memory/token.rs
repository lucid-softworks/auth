use super::{MemoryOAuthProviderStore, State};
use crate::{AuthError, oauth_provider::*};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
impl OAuthProviderTokenStore for MemoryOAuthProviderStore {
    async fn find_oauth_access_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        let state = self.state.read().await;
        Ok(state
            .access_tokens_by_token
            .get(token)
            .and_then(|id| state.access_tokens.get(id))
            .cloned())
    }

    async fn find_oauth_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
        let state = self.state.read().await;
        Ok(state
            .refresh_tokens_by_token
            .get(token)
            .and_then(|id| state.refresh_tokens.get(id))
            .cloned())
    }

    async fn issue_oauth_tokens(&self, issuance: OAuthTokenIssuance) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        validate_token_issuance(&state, &issuance)?;
        if let Some(refresh) = issuance.refresh_token {
            state
                .refresh_tokens_by_token
                .insert(refresh.token.clone(), refresh.id);
            state.refresh_tokens.insert(refresh.id, refresh);
        }
        if let Some(access) = issuance.access_token {
            state
                .access_tokens_by_token
                .insert(access.token.clone(), access.id);
            state.access_tokens.insert(access.id, access);
        }
        Ok(())
    }

    async fn rotate_oauth_refresh_token(
        &self,
        rotation: OAuthRefreshRotation,
    ) -> Result<OAuthRefreshRotationOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(previous) = state
            .refresh_tokens
            .get(&rotation.previous_refresh_id)
            .cloned()
        else {
            return Ok(OAuthRefreshRotationOutcome::NotFound);
        };
        if previous.revoked.is_some() {
            return Ok(OAuthRefreshRotationOutcome::AlreadyConsumed(previous));
        }
        validate_token_issuance(
            &state,
            &OAuthTokenIssuance {
                access_token: rotation.access_token.clone(),
                refresh_token: Some(rotation.next_refresh_token.clone()),
            },
        )?;

        let previous = state
            .refresh_tokens
            .get_mut(&rotation.previous_refresh_id)
            .expect("refresh token was checked above");
        previous.revoked = Some(rotation.rotated_at);
        previous.rotated_at = Some(rotation.rotated_at);
        previous.rotation_replay_expires_at = rotation.replay_expires_at;

        let next = rotation.next_refresh_token;
        state
            .refresh_tokens_by_token
            .insert(next.token.clone(), next.id);
        state.refresh_tokens.insert(next.id, next.clone());
        if let Some(access) = rotation.access_token {
            state
                .access_tokens_by_token
                .insert(access.token.clone(), access.id);
            state.access_tokens.insert(access.id, access);
        }
        Ok(OAuthRefreshRotationOutcome::Rotated(next))
    }

    async fn store_oauth_refresh_rotation_replay(
        &self,
        refresh_id: Uuid,
        response: String,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let Some(refresh) = state.refresh_tokens.get_mut(&refresh_id) else {
            return Ok(false);
        };
        refresh.rotation_replay_response = Some(response);
        Ok(true)
    }

    async fn delete_oauth_access_token(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        let mut state = self.state.write().await;
        let removed = state.access_tokens.remove(&id);
        if let Some(token) = &removed {
            state.access_tokens_by_token.remove(&token.token);
        }
        Ok(removed)
    }

    async fn revoke_oauth_refresh_token(
        &self,
        id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let Some(refresh) = state.refresh_tokens.get_mut(&id) else {
            return Ok(false);
        };
        if refresh.revoked.is_some() {
            return Ok(false);
        }
        refresh.revoked = Some(revoked_at);
        remove_access_tokens(&mut state, |access| access.refresh_id == Some(id));
        Ok(true)
    }

    async fn revoke_oauth_refresh_family(
        &self,
        client_id: &str,
        user_id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let mut state = self.state.write().await;
        let refresh_ids = state
            .refresh_tokens
            .values()
            .filter(|refresh| refresh.client_id == client_id && refresh.user_id == user_id)
            .map(|refresh| refresh.id)
            .collect::<Vec<_>>();
        let access_tokens = remove_access_tokens(&mut state, |access| {
            access
                .refresh_id
                .is_some_and(|refresh_id| refresh_ids.contains(&refresh_id))
        });
        for refresh_id in &refresh_ids {
            if let Some(refresh) = state.refresh_tokens.remove(refresh_id) {
                state.refresh_tokens_by_token.remove(&refresh.token);
            }
        }
        Ok(OAuthTokenRevocationCount {
            access_tokens,
            refresh_tokens: refresh_ids.len(),
        })
    }

    async fn revoke_oauth_tokens_for_authorization_code(
        &self,
        authorization_code_id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let mut state = self.state.write().await;
        let access_tokens = remove_access_tokens(&mut state, |access| {
            access.authorization_code_id.as_deref() == Some(authorization_code_id)
        });
        let refresh_ids = state
            .refresh_tokens
            .values()
            .filter(|refresh| {
                refresh.authorization_code_id.as_deref() == Some(authorization_code_id)
            })
            .map(|refresh| refresh.id)
            .collect::<Vec<_>>();
        for refresh_id in &refresh_ids {
            if let Some(refresh) = state.refresh_tokens.remove(refresh_id) {
                state.refresh_tokens_by_token.remove(&refresh.token);
            }
        }
        Ok(OAuthTokenRevocationCount {
            access_tokens,
            refresh_tokens: refresh_ids.len(),
        })
    }

    async fn revoke_oauth_tokens_for_session(
        &self,
        session_id: &str,
        revoked_at: DateTime<Utc>,
        preserve_offline_access: bool,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        let mut state = self.state.write().await;
        let mut counts = OAuthTokenRevocationCount::default();
        for access in state.access_tokens.values_mut().filter(|access| {
            access.session_id.as_deref() == Some(session_id) && access.revoked.is_none()
        }) {
            access.revoked = Some(revoked_at);
            counts.access_tokens += 1;
        }
        for refresh in state.refresh_tokens.values_mut().filter(|refresh| {
            refresh.session_id.as_deref() == Some(session_id)
                && refresh.revoked.is_none()
                && !(preserve_offline_access
                    && refresh.scopes.iter().any(|scope| scope == "offline_access"))
        }) {
            refresh.revoked = Some(revoked_at);
            counts.refresh_tokens += 1;
        }
        Ok(counts)
    }

    async fn prepare_oauth_session_logout(
        &self,
        session_id: &str,
    ) -> Result<OAuthSessionLogoutPlan, AuthError> {
        let state = self.state.read().await;
        let access = state
            .access_tokens
            .values()
            .filter(|token| token.session_id.as_deref() == Some(session_id));
        let refresh = state
            .refresh_tokens
            .values()
            .filter(|token| token.session_id.as_deref() == Some(session_id));
        let mut client_ids = access
            .clone()
            .map(|token| token.client_id.clone())
            .chain(refresh.clone().map(|token| token.client_id.clone()))
            .collect::<Vec<_>>();
        client_ids.sort();
        client_ids.dedup();
        Ok(OAuthSessionLogoutPlan {
            client_ids,
            access_token_ids: access
                .filter(|token| token.revoked.is_none())
                .map(|token| token.id)
                .collect(),
            refresh_token_ids: refresh
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
        let mut state = self.state.write().await;
        let mut counts = OAuthTokenRevocationCount::default();
        for id in &plan.access_token_ids {
            if let Some(token) = state.access_tokens.get_mut(id)
                && token.revoked.is_none()
            {
                token.revoked = Some(revoked_at);
                counts.access_tokens += 1;
            }
        }
        for id in &plan.refresh_token_ids {
            if let Some(token) = state.refresh_tokens.get_mut(id)
                && token.revoked.is_none()
            {
                token.revoked = Some(revoked_at);
                counts.refresh_tokens += 1;
            }
        }
        Ok(counts)
    }
}

fn validate_token_issuance(state: &State, issuance: &OAuthTokenIssuance) -> Result<(), AuthError> {
    if let Some(refresh) = &issuance.refresh_token
        && (state.refresh_tokens.contains_key(&refresh.id)
            || state.refresh_tokens_by_token.contains_key(&refresh.token))
    {
        return Err(AuthError::Storage(
            "OAuth refresh token identifier already exists".into(),
        ));
    }
    if let Some(access) = &issuance.access_token {
        if state.access_tokens.contains_key(&access.id)
            || state.access_tokens_by_token.contains_key(&access.token)
        {
            return Err(AuthError::Storage(
                "OAuth access token identifier already exists".into(),
            ));
        }
        if let Some(refresh_id) = access.refresh_id
            && issuance
                .refresh_token
                .as_ref()
                .is_none_or(|refresh| refresh.id != refresh_id)
            && !state.refresh_tokens.contains_key(&refresh_id)
        {
            return Err(AuthError::Storage(
                "OAuth access token references an unknown refresh token".into(),
            ));
        }
    }
    Ok(())
}

fn remove_access_tokens(
    state: &mut State,
    predicate: impl Fn(&OAuthProviderAccessToken) -> bool,
) -> usize {
    let ids = state
        .access_tokens
        .values()
        .filter(|access| predicate(access))
        .map(|access| access.id)
        .collect::<Vec<_>>();
    for id in &ids {
        if let Some(access) = state.access_tokens.remove(id) {
            state.access_tokens_by_token.remove(&access.token);
        }
    }
    ids.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn refresh(token: &str, user_id: Uuid) -> OAuthProviderRefreshToken {
        OAuthProviderRefreshToken {
            id: Uuid::new_v4(),
            token: token.into(),
            client_id: "client".into(),
            session_id: None,
            user_id: user_id.to_string(),
            reference_id: None,
            authorization_code_id: None,
            resources: None,
            requested_user_info_claims: None,
            expires_at: Utc::now() + Duration::days(30),
            created_at: Utc::now(),
            revoked: None,
            rotated_at: None,
            rotation_replay_response: None,
            rotation_replay_expires_at: None,
            auth_time: None,
            confirmation: None,
            scopes: vec!["offline_access".into()],
        }
    }

    #[tokio::test]
    async fn refresh_rotation_is_compare_and_swap() {
        let store = MemoryOAuthProviderStore::new();
        let user_id = Uuid::new_v4();
        let original = refresh("old", user_id);
        store
            .issue_oauth_tokens(OAuthTokenIssuance {
                access_token: None,
                refresh_token: Some(original.clone()),
            })
            .await
            .unwrap();
        let next = refresh("new", user_id);
        let rotation = OAuthRefreshRotation {
            previous_refresh_id: original.id,
            rotated_at: Utc::now(),
            replay_expires_at: None,
            next_refresh_token: next.clone(),
            access_token: None,
        };
        assert!(matches!(
            store
                .rotate_oauth_refresh_token(rotation.clone())
                .await
                .unwrap(),
            OAuthRefreshRotationOutcome::Rotated(_)
        ));
        assert!(matches!(
            store.rotate_oauth_refresh_token(rotation).await.unwrap(),
            OAuthRefreshRotationOutcome::AlreadyConsumed(_)
        ));
        assert_eq!(
            store
                .find_oauth_refresh_token("new")
                .await
                .unwrap()
                .unwrap()
                .id,
            next.id
        );
    }
}
