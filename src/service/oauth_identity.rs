use super::{AuthService, SignInResult};
use crate::{
    AuthError, AuthUser, AuthenticationMethod, DatabaseModel, DatabaseRecord, OAuthAccount,
    OAuthTokens, OAuthUserInfo, oauth::crypto,
};
use chrono::Utc;
use uuid::Uuid;

pub(super) struct OAuthSignInPolicy {
    pub provider_id: String,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub require_email_verification: bool,
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
            .await?;
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
            account.id = owner.account.id;
            account.user_id = owner.user.id;
            account.created_at = owner.account.created_at;
            super::account_lifecycle::preserve_oauth_tokens(&mut account, &owner.account);
            let account = self.prepare_account_update(account).await?;
            let account = self.store.update_oauth_account_tokens(account).await?;
            self.finish_account_update(&account).await?;
            self.persist_oauth_email_verification(&owner.user, &user_info)
                .await?;
            return Ok((owner.user, false));
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
            account.user_id = user.id;
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
                user.id,
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
            id: Uuid::new_v4(),
            username: None,
            display_username: None,
            name: user_info.name,
            email: user_info.email,
            email_verified: user_info.email_verified,
            image: user_info.image,
            additional_fields: self
                .create_additional_fields(DatabaseModel::User, serde_json::Map::new())?,
            role: self.default_user_role(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        };
        let user = match self
            .before_database_create(DatabaseRecord::User(user))
            .await?
        {
            DatabaseRecord::User(user) => user,
            _ => unreachable!("database hook model was validated"),
        };
        account.user_id = user.id;
        let account = self.prepare_account_create(account).await?;
        let owner = self.store.create_oauth_user(user, account).await?;
        self.after_database_create(&DatabaseRecord::User(owner.user.clone()))
            .await?;
        self.finish_account_create(&owner.account).await?;
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
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            issuer: user_info.issuer.clone(),
            account_id: user_info.account_id.clone(),
            provider_id: provider_id.into(),
            access_token: crypto::encrypt(&self.config.secret, tokens.access_token)?,
            refresh_token: crypto::encrypt(&self.config.secret, tokens.refresh_token)?,
            id_token: crypto::encrypt(&self.config.secret, tokens.id_token)?,
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
