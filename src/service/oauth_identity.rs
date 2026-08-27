use super::{AuthService, SignInResult};
use crate::{
    AuthError, AuthUser, AuthenticationMethod, DatabaseModel, DatabaseRecord, OAuthAccount,
    OAuthTokens, OAuthUserInfo,
};
use chrono::Utc;

pub(super) struct OAuthSignInPolicy {
    pub provider_id: String,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub require_email_verification: bool,
    pub override_user_info: bool,
}

impl AuthService {
    pub(super) async fn finish_oauth_sign_in(
        &self,
        provider: &dyn crate::SocialProvider,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
        request_sign_up: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SignInResult, bool), AuthError> {
        self.finish_oauth_sign_in_with_policy(
            &OAuthSignInPolicy {
                provider_id: provider.id().into(),
                disable_implicit_sign_up: provider.disable_implicit_sign_up(),
                disable_sign_up: provider.disable_sign_up(),
                require_email_verification: provider.require_email_verification(),
                override_user_info: provider.override_user_info(),
            },
            tokens,
            user_info,
            request_sign_up,
            ip_address,
            user_agent,
        )
        .await
    }

    pub(super) async fn finish_oauth_sign_in_with_policy(
        &self,
        policy: &OAuthSignInPolicy,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
        request_sign_up: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SignInResult, bool), AuthError> {
        let now = Utc::now();
        let account = self.oauth_account(&policy.provider_id, &user_info, tokens, now)?;
        let (user, is_new_user) = self
            .resolve_oauth_user(policy, user_info, account, request_sign_up, now)
            .await?;
        if policy.require_email_verification && !user.email_verified {
            let should_send = if is_new_user {
                self.config
                    .email_verification
                    .send_on_sign_up
                    .unwrap_or(true)
            } else {
                self.config.email_verification.send_on_sign_in
            };
            if should_send
                && (self.config.email_verification.sender.is_some()
                    || self.email_otp_overrides_verification())
            {
                let _ = self.deliver_verification_email(user.clone(), None).await;
            }
            return Err(AuthError::EmailNotVerified);
        }
        let session = self
            .create_session(
                user,
                AuthenticationMethod::OAuth,
                None,
                ip_address,
                user_agent,
            )
            .await
            .map_err(|_| AuthError::OAuthUnableToCreateSession)?;
        Ok((session, is_new_user))
    }

    async fn resolve_oauth_user(
        &self,
        policy: &OAuthSignInPolicy,
        user_info: OAuthUserInfo,
        mut account: OAuthAccount,
        request_sign_up: bool,
        now: chrono::DateTime<Utc>,
    ) -> Result<(AuthUser, bool), AuthError> {
        if let Some(owner) = self
            .store
            .find_oauth_account_owner(&user_info.issuer, &user_info.account_id)
            .await?
        {
            account.id.clone_from(&owner.account.id);
            account.user_id.clone_from(&owner.user.id);
            account.created_at = owner.account.created_at;
            super::account_lifecycle::preserve_oauth_tokens(&mut account, &owner.account);
            let account = self
                .prepare_account_update(account)
                .await
                .map_err(|_| AuthError::OAuthUnableToUpdateAccount)?;
            let account = self
                .store
                .update_oauth_account_tokens(account)
                .await
                .map_err(|_| AuthError::OAuthUnableToUpdateAccount)?;
            self.finish_account_update(&account)
                .await
                .map_err(|_| AuthError::OAuthUnableToUpdateAccount)?;
            let user = if policy.override_user_info {
                self.override_oauth_user_info(owner.user, &user_info)
                    .await?
            } else {
                owner.user
            };
            self.persist_oauth_email_verification(&user, &user_info)
                .await?;
            return Ok((user, false));
        }
        if let Some(user) = self.store.find_user_by_email(&user_info.email).await? {
            let trusted = self
                .config
                .trusted_social_providers
                .iter()
                .any(|trusted| trusted == &policy.provider_id);
            let linking = &self.config.account.account_linking;
            if !linking.enabled
                || linking.disable_implicit_linking
                || (!trusted && !user_info.email_verified)
                || (linking.require_local_email_verified && !user.email_verified)
            {
                return Err(AuthError::OAuthAccountNotLinked);
            }
            account.user_id = user.id.clone();
            let account = self.prepare_account_create(account).await?;
            let account = self.store.link_oauth_account(account).await?;
            self.finish_account_create(&account).await?;
            self.persist_oauth_email_verification(&user, &user_info)
                .await?;
            return Ok((user, false));
        }
        self.create_social_user(policy, user_info, account, request_sign_up, now)
            .await
    }

    async fn override_oauth_user_info(
        &self,
        mut user: AuthUser,
        info: &OAuthUserInfo,
    ) -> Result<AuthUser, AuthError> {
        let additional_fields =
            self.update_additional_fields(DatabaseModel::User, info.additional_fields.clone())?;
        user = self
            .store
            .update_user_profile(
                &user.id,
                crate::UserProfileUpdate {
                    name: Some(info.name.clone()),
                    image: Some(info.image.clone()),
                    additional_fields,
                    ..crate::UserProfileUpdate::default()
                },
            )
            .await?
            .ok_or_else(|| AuthError::Storage("OAuth user disappeared during update".into()))?;
        if user.email != info.email {
            user = self
                .store
                .update_user_email(&user.id, &user.email, &info.email, info.email_verified)
                .await?
                .ok_or_else(|| AuthError::Storage("OAuth user disappeared during update".into()))?;
        }
        Ok(user)
    }

    async fn persist_oauth_email_verification(
        &self,
        user: &AuthUser,
        user_info: &OAuthUserInfo,
    ) -> Result<(), AuthError> {
        if user.email_verified || !user_info.email_verified || user.email != user_info.email {
            return Ok(());
        }
        let mut candidate = user.clone();
        candidate.email_verified = true;
        candidate.updated_at = Utc::now();
        let candidate = self.prepare_user_update(user, candidate).await?;
        let updated = self
            .store
            .update_user_email(
                &user.id,
                &user.email,
                &candidate.email,
                candidate.email_verified,
            )
            .await?
            .ok_or_else(|| AuthError::Storage("OAuth user disappeared during update".into()))?;
        self.after_database_update(&DatabaseRecord::User(updated))
            .await
    }

    async fn create_social_user(
        &self,
        policy: &OAuthSignInPolicy,
        user_info: OAuthUserInfo,
        mut account: OAuthAccount,
        request_sign_up: bool,
        now: chrono::DateTime<Utc>,
    ) -> Result<(AuthUser, bool), AuthError> {
        if policy.disable_sign_up || (policy.disable_implicit_sign_up && !request_sign_up) {
            return Err(AuthError::OAuthSignupDisabled);
        }
        let user = AuthUser {
            id: String::new(),
            username: None,
            display_username: None,
            name: user_info.name,
            email: user_info.email,
            email_verified: user_info.email_verified,
            image: user_info.image,
            additional_fields: self
                .create_additional_fields(DatabaseModel::User, user_info.additional_fields)?,
            role: self.default_user_role(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        };
        let user = self
            .prepare_user_create_with_prepared_fields(user)
            .await
            .map_err(|_| AuthError::OAuthUnableToCreateUser)?;
        account.user_id.clear();
        let account = self.oauth_account_create(account);
        let owner = self
            .store
            .create_oauth_user(user, &account)
            .await
            .map_err(|_| AuthError::OAuthUnableToCreateUser)?;
        self.after_database_create(&DatabaseRecord::User(owner.user.clone()))
            .await
            .map_err(|_| AuthError::OAuthUnableToCreateUser)?;
        self.finish_account_create(&owner.account)
            .await
            .map_err(|_| AuthError::OAuthUnableToCreateUser)?;
        Ok((owner.user, true))
    }

    pub(super) fn oauth_account(
        &self,
        provider_id: &str,
        user_info: &OAuthUserInfo,
        tokens: OAuthTokens,
        now: chrono::DateTime<Utc>,
    ) -> Result<OAuthAccount, AuthError> {
        Ok(OAuthAccount {
            id: String::new(),
            user_id: String::new(),
            issuer: user_info.issuer.clone(),
            account_id: user_info.account_id.clone(),
            provider_id: provider_id.into(),
            access_token: self.protect_oauth_token(tokens.access_token)?,
            refresh_token: self.protect_oauth_token(tokens.refresh_token)?,
            id_token: tokens.id_token,
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
            password: None,
            additional_fields: serde_json::Map::new(),
            created_at: now,
            updated_at: now,
        })
    }
}
