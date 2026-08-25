use super::{
    AuthService,
    account_types::{
        LinkedAccount, ProviderAccountIdentity, ProviderAccountInfo, ProviderAccountUser,
        ProviderTokenResponse, parse_scopes,
    },
    oauth::{SocialIdTokenInput, SocialSignInInput, SocialSignInResult},
    oauth_state::OAuthLinkState,
};
use crate::{
    AccountDeleteOutcome, AuthError, OAuthAccount, OAuthTokens, OAuthUserInfo, SessionWithUser,
};
use chrono::{Duration, Utc};
use serde_json::Value;
use uuid::Uuid;

impl AuthService {
    pub async fn list_linked_accounts(
        &self,
        actor: &SessionWithUser,
    ) -> Result<Vec<LinkedAccount>, AuthError> {
        require_account_session(actor)?;
        let configured = self.database_schema_fields(crate::DatabaseModel::Account);
        Ok(self
            .store
            .list_user_accounts(actor.user.id)
            .await?
            .into_iter()
            .map(|mut account| {
                account.additional_fields = crate::additional_fields::filtered_output(
                    configured,
                    account.additional_fields,
                );
                account
            })
            .map(LinkedAccount::from)
            .collect())
    }

    pub async fn unlink_account(
        &self,
        actor: &SessionWithUser,
        account_id: Uuid,
    ) -> Result<(), AuthError> {
        require_fresh_session(self, actor)?;
        let account = self
            .store
            .list_user_accounts(actor.user.id)
            .await?
            .into_iter()
            .find(|account| account.id == account_id);
        if let Some(account) = &account {
            self.before_database_delete(&crate::DatabaseRecord::Account(account.clone()))
                .await?;
        }
        let outcome = self
            .store
            .delete_user_account(
                actor.user.id,
                account_id,
                self.config.account.account_linking.allow_unlinking_all,
            )
            .await?;
        match outcome {
            AccountDeleteOutcome::Deleted => {
                if let Some(account) = account {
                    self.after_database_delete(&crate::DatabaseRecord::Account(account))
                        .await?;
                }
                Ok(())
            }
            AccountDeleteOutcome::NotFound => Err(AuthError::AccountNotFound),
            AccountDeleteOutcome::LastAccount => Err(AuthError::FailedToUnlinkLastAccount),
        }
    }

    pub async fn link_social_account(
        &self,
        actor: &SessionWithUser,
        input: SocialSignInInput,
    ) -> Result<SocialSignInResult, AuthError> {
        require_account_session(actor)?;
        if input
            .additional_params
            .keys()
            .any(|name| crate::oauth::authorization_parameter_is_reserved(name))
        {
            return Err(AuthError::InvalidRequest(
                "OAuth authorization parameters contain a reserved name".into(),
            ));
        }
        let provider = self
            .social_provider(&input.provider)
            .ok_or(AuthError::OAuthProviderNotFound)?;
        let link = OAuthLinkState {
            user_id: actor.user.id,
            email: actor.user.email.clone(),
        };
        if let Some(id_token) = input.id_token.clone() {
            self.link_social_id_token(provider.as_ref(), &link, id_token)
                .await?;
            return Ok(SocialSignInResult::Linked);
        }
        self.start_social_authorization(provider.as_ref(), input, Some(link), None, None)
            .await
    }

    async fn link_social_id_token(
        &self,
        provider: &dyn crate::SocialProvider,
        link: &OAuthLinkState,
        input: SocialIdTokenInput,
    ) -> Result<(), AuthError> {
        if !provider.supports_id_token_sign_in() {
            return Err(AuthError::OAuthIdTokenNotSupported);
        }
        let tokens = OAuthTokens {
            access_token: input.access_token,
            refresh_token: input.refresh_token,
            id_token: Some(input.token),
            ..OAuthTokens::default()
        };
        let user_info = provider
            .get_user_info(&tokens, input.nonce.as_deref(), input.user.as_ref())
            .await?;
        self.link_oauth_identity(provider, link, tokens, user_info)
            .await
    }

    pub(super) async fn link_oauth_identity(
        &self,
        provider: &dyn crate::SocialProvider,
        link: &OAuthLinkState,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
    ) -> Result<(), AuthError> {
        let user = self
            .store
            .find_user_by_email(&link.email)
            .await?
            .filter(|user| user.id == link.user_id)
            .ok_or(AuthError::Unauthorized)?;
        if !self.config.account.account_linking.enabled {
            return Err(AuthError::LinkingNotAllowed);
        }
        let mut account = self.oauth_account(provider.id(), &user_info, tokens, Utc::now())?;
        if let Some(owner) = self
            .store
            .find_oauth_account_owner(&user_info.issuer, &user_info.account_id)
            .await?
        {
            if owner.user.id != user.id {
                return Err(AuthError::SocialAccountAlreadyLinked);
            }
            account.id = owner.account.id;
            account.user_id = user.id;
            account.created_at = owner.account.created_at;
            preserve_oauth_tokens(&mut account, &owner.account);
            let account = self.prepare_account_update(account).await?;
            let account = self.store.update_oauth_account_tokens(account).await?;
            self.finish_account_update(&account).await?;
            return Ok(());
        }
        let trusted = self
            .config
            .trusted_social_providers
            .iter()
            .any(|id| id == provider.id());
        if !trusted && !user_info.email_verified {
            return Err(AuthError::LinkingNotAllowed);
        }
        if !self.config.account.account_linking.allow_different_emails
            && !user.email.eq_ignore_ascii_case(&user_info.email)
        {
            return Err(AuthError::LinkingDifferentEmailsNotAllowed);
        }
        account.user_id = user.id;
        let account = self
            .prepare_account_create(account)
            .await
            .map_err(|_| AuthError::OAuthUnableToLinkAccount)?;
        let account = self
            .store
            .link_oauth_account(account)
            .await
            .map_err(|_| AuthError::OAuthUnableToLinkAccount)?;
        self.finish_account_create(&account)
            .await
            .map_err(|_| AuthError::OAuthUnableToLinkAccount)?;
        Ok(())
    }

    pub async fn get_provider_access_token(
        &self,
        actor: &SessionWithUser,
        account_id: Uuid,
    ) -> Result<ProviderTokenResponse, AuthError> {
        require_account_session(actor)?;
        let account = self.account_for_user(actor.user.id, account_id).await?;
        self.get_provider_access_token_for_account(account).await
    }

    pub(super) async fn get_provider_access_token_for_account(
        &self,
        account: OAuthAccount,
    ) -> Result<ProviderTokenResponse, AuthError> {
        let expiring = account
            .access_token_expires_at
            .is_some_and(|expires| expires - Utc::now() < Duration::seconds(5));
        if expiring && account.refresh_token.is_some() {
            return self.refresh_provider_account(account).await;
        }
        self.account_token_response(account, false)
            .map_err(|_| AuthError::OAuthFailedToGetAccessToken)
    }

    pub async fn provider_account_info(
        &self,
        actor: &SessionWithUser,
        account_id: Uuid,
    ) -> Result<ProviderAccountInfo, AuthError> {
        let account = self.account_for_user(actor.user.id, account_id).await?;
        self.provider_account_info_for_account(account).await
    }

    pub(super) async fn provider_account_info_for_account(
        &self,
        account: OAuthAccount,
    ) -> Result<ProviderAccountInfo, AuthError> {
        let provider = self
            .social_provider(&account.provider_id)
            .ok_or(AuthError::OAuthProviderNotConfigured)?;
        let tokens = self
            .get_provider_access_token_for_account(account.clone())
            .await?;
        if tokens.access_token.is_empty() {
            return Err(AuthError::OAuthAccessTokenNotFound);
        }
        let info = provider
            .get_user_info(
                &OAuthTokens {
                    access_token: Some(tokens.access_token),
                    id_token: tokens.id_token,
                    ..OAuthTokens::default()
                },
                None,
                None,
            )
            .await?;
        Ok(provider_account_info(account, info))
    }

    pub(super) async fn account_for_user(
        &self,
        user_id: Uuid,
        account_id: Uuid,
    ) -> Result<OAuthAccount, AuthError> {
        self.store
            .list_user_accounts(user_id)
            .await?
            .into_iter()
            .find(|account| account.id == account_id)
            .ok_or(AuthError::AccountNotFound)
    }

    pub(super) fn account_token_response(
        &self,
        account: OAuthAccount,
        refreshed: bool,
    ) -> Result<ProviderTokenResponse, AuthError> {
        Ok(ProviderTokenResponse {
            access_token: self
                .unprotect_oauth_token(account.access_token.as_deref())?
                .unwrap_or_default(),
            access_token_expires_at: account.access_token_expires_at,
            refresh_token: if refreshed {
                self.unprotect_oauth_token(account.refresh_token.as_deref())?
            } else {
                None
            },
            refresh_token_expires_at: refreshed
                .then_some(account.refresh_token_expires_at)
                .flatten(),
            scopes: (!refreshed).then(|| parse_scopes(account.scope.as_deref())),
            scope: refreshed.then_some(account.scope.clone()).flatten(),
            id_token: account.id_token,
            provider_id: refreshed.then_some(account.provider_id),
            account_id: refreshed.then_some(account.id),
        })
    }
}

pub(super) fn preserve_oauth_tokens(account: &mut OAuthAccount, previous: &OAuthAccount) {
    account.scope = merge_scopes(previous.scope.as_deref(), account.scope.as_deref());
    account
        .additional_fields
        .clone_from(&previous.additional_fields);
    if account.access_token.is_none() {
        account.access_token.clone_from(&previous.access_token);
    }
    if account.refresh_token.is_none() {
        account.refresh_token.clone_from(&previous.refresh_token);
    }
    if account.id_token.is_none() {
        account.id_token.clone_from(&previous.id_token);
    }
    if account.access_token_expires_at.is_none() {
        account
            .access_token_expires_at
            .clone_from(&previous.access_token_expires_at);
    }
    if account.refresh_token_expires_at.is_none() {
        account
            .refresh_token_expires_at
            .clone_from(&previous.refresh_token_expires_at);
    }
}

fn merge_scopes(stored: Option<&str>, incoming: Option<&str>) -> Option<String> {
    let mut merged = Vec::new();
    for scope in stored
        .into_iter()
        .chain(incoming)
        .flat_map(|scopes| scopes.split(','))
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
    {
        if !merged.contains(&scope) {
            merged.push(scope);
        }
    }
    (!merged.is_empty()).then(|| merged.join(","))
}

fn provider_account_info(account: OAuthAccount, info: OAuthUserInfo) -> ProviderAccountInfo {
    ProviderAccountInfo {
        user: ProviderAccountUser {
            name: info.name,
            email: info.email,
            image: info.image,
            email_verified: info.email_verified,
        },
        data: Value::Object(info.profile),
        account: ProviderAccountIdentity {
            id: account.id,
            provider_id: account.provider_id,
            issuer: account.issuer,
            account_id: account.account_id,
        },
    }
}

pub(super) fn require_account_session(actor: &SessionWithUser) -> Result<(), AuthError> {
    if actor.user.is_anonymous || actor.session.actor_user_id.is_some() {
        Err(AuthError::Unauthorized)
    } else {
        Ok(())
    }
}

fn require_fresh_session(service: &AuthService, actor: &SessionWithUser) -> Result<(), AuthError> {
    require_account_session(actor)?;
    if service.config.session_fresh_age != Duration::zero()
        && actor.session.created_at + service.config.session_fresh_age <= Utc::now()
    {
        return Err(AuthError::SessionNotFresh);
    }
    Ok(())
}
