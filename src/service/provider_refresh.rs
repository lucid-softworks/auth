use super::{AuthService, account_lifecycle::require_account_session};
use crate::{
    AuthError, OAuthAccount, OAuthRefreshContext, OAuthTokenUpdateOutcome, OAuthTokens,
    ProviderTokenResponse, SessionWithUser,
};
use chrono::Utc;
use uuid::Uuid;

impl AuthService {
    pub async fn refresh_provider_access_token(
        &self,
        actor: &SessionWithUser,
        account_id: Uuid,
    ) -> Result<ProviderTokenResponse, AuthError> {
        require_account_session(actor)?;
        let account = self.account_for_user(actor.user.id, account_id).await?;
        self.refresh_provider_account(account).await
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn refresh_provider_access_token_with_context(
        &self,
        actor: &SessionWithUser,
        account_id: Uuid,
        context: &OAuthRefreshContext,
    ) -> Result<ProviderTokenResponse, AuthError> {
        require_account_session(actor)?;
        let account = self.account_for_user(actor.user.id, account_id).await?;
        self.refresh_provider_account_with_context(account, context)
            .await
    }

    pub(super) async fn refresh_provider_account(
        &self,
        account: OAuthAccount,
    ) -> Result<ProviderTokenResponse, AuthError> {
        self.refresh_provider_account_with_context(account, &OAuthRefreshContext::default())
            .await
    }

    pub(super) async fn refresh_provider_account_with_context(
        &self,
        mut account: OAuthAccount,
        context: &OAuthRefreshContext,
    ) -> Result<ProviderTokenResponse, AuthError> {
        let provider = self
            .social_provider(&account.provider_id)
            .ok_or_else(|| AuthError::OAuthProviderNotSupported(account.provider_id.clone()))?;
        if !provider.supports_token_refresh() {
            return Err(AuthError::OAuthTokenRefreshNotSupported(
                account.provider_id.clone(),
            ));
        }
        let expected_refresh = account.refresh_token.clone();
        let expected_updated = account.updated_at;
        let refresh = self
            .unprotect_oauth_token(account.refresh_token.as_deref())
            .map_err(|_| AuthError::OAuthFailedToRefreshToken)?
            .ok_or(AuthError::OAuthRefreshTokenNotFound)?;
        let tokens = match provider
            .refresh_access_token_with_context(&refresh, context)
            .await
        {
            Ok(tokens) => tokens,
            Err(_) => {
                let current = self.account_for_user(account.user_id, account.id).await?;
                if current.updated_at != expected_updated {
                    return self
                        .account_token_response(current, true)
                        .map_err(|_| AuthError::OAuthFailedToRefreshToken);
                }
                return Err(AuthError::OAuthFailedToRefreshToken);
            }
        };
        apply_refreshed_tokens(self, &mut account, tokens)?;
        let account = match self
            .store
            .compare_and_swap_oauth_tokens(account, expected_refresh.as_deref(), expected_updated)
            .await?
        {
            OAuthTokenUpdateOutcome::Updated(account) | OAuthTokenUpdateOutcome::Stale(account) => {
                account
            }
            OAuthTokenUpdateOutcome::NotFound => return Err(AuthError::AccountNotFound),
        };
        self.account_token_response(account, true)
            .map_err(|_| AuthError::OAuthFailedToRefreshToken)
    }
}

fn apply_refreshed_tokens(
    service: &AuthService,
    account: &mut OAuthAccount,
    tokens: OAuthTokens,
) -> Result<(), AuthError> {
    if let Some(token) = tokens.access_token {
        account.access_token = service.protect_oauth_token(Some(token))?;
    }
    if let Some(token) = tokens.refresh_token {
        account.refresh_token = service.protect_oauth_token(Some(token))?;
    }
    if let Some(token) = tokens.id_token {
        account.id_token = Some(token);
    }
    account.access_token_expires_at = tokens.access_token_expires_at;
    account.refresh_token_expires_at = tokens
        .refresh_token_expires_at
        .or(account.refresh_token_expires_at);
    account.updated_at = Utc::now();
    Ok(())
}
