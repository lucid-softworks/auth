use super::{OAuthSignInPolicy, sso_conflict};
use crate::service::AuthService;
use crate::{AuthError, AuthUser, DatabaseModel, DatabaseRecord, OAuthAccount, OAuthUserInfo};
use chrono::Utc;

impl AuthService {
    pub(super) async fn resolve_oauth_user(
        &self,
        policy: &OAuthSignInPolicy,
        user_info: OAuthUserInfo,
        account: OAuthAccount,
        request_sign_up: bool,
        now: chrono::DateTime<Utc>,
    ) -> Result<(AuthUser, bool), AuthError> {
        if let Some(owner) = self
            .find_oauth_account_owner(&user_info.issuer, &user_info.account_id)
            .await?
        {
            return self
                .finish_existing_owner(policy, user_info, account, owner)
                .await;
        }
        if let Some(selected) = &policy.selected_user {
            return self
                .link_selected_user(policy, selected, user_info, account)
                .await;
        }
        if let Some(user) = self.find_oauth_user_by_email(&user_info.email).await? {
            return self
                .link_email_user(policy, user_info, account, user)
                .await;
        }
        self.create_social_user(policy, user_info, account, request_sign_up, now)
            .await
    }

    async fn finish_existing_owner(
        &self,
        policy: &OAuthSignInPolicy,
        user_info: OAuthUserInfo,
        mut account: OAuthAccount,
        owner: crate::OAuthAccountOwner,
    ) -> Result<(AuthUser, bool), AuthError> {
        if policy
            .selected_user
            .as_ref()
            .is_some_and(|selected| selected.user_id != owner.user.id)
        {
            return Err(sso_conflict(
                "account_ownership_conflict",
                "Account is already linked to another user",
            ));
        }
        if policy.require_exact_account_binding && owner.account.provider_id != policy.provider_id {
            return Err(sso_conflict(
                "account_provider_conflict",
                "Account is already linked through another provider",
            ));
        }
        account.id.clone_from(&owner.account.id);
        account.user_id.clone_from(&owner.user.id);
        account.created_at = owner.account.created_at;
        super::super::account_lifecycle::preserve_oauth_tokens(&mut account, &owner.account);
        let account = self
            .prepare_account_update(account)
            .await
            .map_err(|_| AuthError::OAuthUnableToUpdateAccount)?;
        let account = self
            .write_oauth_account_update(account)
            .await
            .map_err(|_| AuthError::OAuthUnableToUpdateAccount)?;
        ensure_account_binding(policy, &account, &owner.user.id, &user_info)?;
        self.finish_account_update(&account)
            .await
            .map_err(|_| AuthError::OAuthUnableToUpdateAccount)?;
        let update_profile = policy
            .selected_user
            .as_ref()
            .map(|selected| selected.update_profile)
            .unwrap_or(policy.override_user_info);
        let user = if update_profile {
            self.override_oauth_user_info(owner.user, &user_info)
                .await?
        } else {
            owner.user
        };
        self.persist_oauth_email_verification(&user, &user_info)
            .await?;
        Ok((user, false))
    }

    async fn link_selected_user(
        &self,
        policy: &OAuthSignInPolicy,
        selected: &super::OAuthSelectedUser,
        user_info: OAuthUserInfo,
        mut account: OAuthAccount,
    ) -> Result<(AuthUser, bool), AuthError> {
        let Some(mut user) = self.store.find_user_by_id(&selected.user_id).await? else {
            return Err(sso_conflict("user_not_found", "User not found"));
        };
        account.user_id.clone_from(&user.id);
        let account = self.prepare_account_create(account).await?;
        let account = self.write_oauth_account_create(account).await?;
        ensure_account_binding(policy, &account, &user.id, &user_info)?;
        self.finish_account_create(&account).await?;
        if selected.update_profile {
            user = self.override_oauth_user_info(user, &user_info).await?;
            if user.id != selected.user_id {
                return Err(sso_conflict(
                    "user_hook_selection_conflict",
                    "User hook changed the selected user",
                ));
            }
        }
        Ok((user, false))
    }

    async fn link_email_user(
        &self,
        policy: &OAuthSignInPolicy,
        user_info: OAuthUserInfo,
        mut account: OAuthAccount,
        user: AuthUser,
    ) -> Result<(AuthUser, bool), AuthError> {
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
        account.user_id.clone_from(&user.id);
        let account = self.prepare_account_create(account).await?;
        let account = self.write_oauth_account_create(account).await?;
        ensure_account_binding(policy, &account, &user.id, &user_info)?;
        self.finish_account_create(&account).await?;
        self.persist_oauth_email_verification(&user, &user_info)
            .await?;
        Ok((user, false))
    }

    async fn override_oauth_user_info(
        &self,
        mut user: AuthUser,
        info: &OAuthUserInfo,
    ) -> Result<AuthUser, AuthError> {
        let additional_fields =
            self.update_additional_fields(DatabaseModel::User, info.additional_fields.clone())?;
        if let Some(transaction) = crate::database_hooks::current_transaction() {
            let original = user.clone();
            user.name.clone_from(&info.name);
            user.image.clone_from(&info.image);
            user.additional_fields.extend(additional_fields);
            user.email.clone_from(&info.email);
            user.email_verified = if user.email == original.email {
                original.email_verified || info.email_verified
            } else {
                info.email_verified
            };
            user.updated_at = Utc::now();
            let user = self.prepare_user_update(&original, user).await?;
            let DatabaseRecord::User(user) = transaction.update(DatabaseRecord::User(user)).await?
            else {
                unreachable!("transaction update preserves its model")
            };
            self.after_database_update(&DatabaseRecord::User(user.clone()))
                .await?;
            return Ok(user);
        }
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
        if let Some(transaction) = crate::database_hooks::current_transaction() {
            let DatabaseRecord::User(updated) = transaction
                .update(DatabaseRecord::User(candidate))
                .await?
            else {
                unreachable!("transaction update preserves its model")
            };
            return self
                .after_database_update(&DatabaseRecord::User(updated))
                .await;
        }
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
        let binding = user_info.clone();
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
        account.user_id.clear();
        let owner = self
            .create_user_and_oauth_account(user, account)
            .await
            .map_err(|_| AuthError::OAuthUnableToCreateUser)?;
        ensure_account_binding(policy, &owner.account, &owner.user.id, &binding)?;
        Ok((owner.user, true))
    }

    async fn find_oauth_account_owner(
        &self,
        issuer: &str,
        account_id: &str,
    ) -> Result<Option<crate::OAuthAccountOwner>, AuthError> {
        match crate::database_hooks::current_transaction() {
            Some(transaction) => transaction.find_oauth_account_owner(issuer, account_id).await,
            None => self
                .store
                .find_oauth_account_owner(issuer, account_id)
                .await,
        }
    }

    async fn find_oauth_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        match crate::database_hooks::current_transaction() {
            Some(transaction) => transaction.find_user_by_email(email).await,
            None => self.store.find_user_by_email(email).await,
        }
    }

    async fn write_oauth_account_create(
        &self,
        account: crate::DatabaseCreate<OAuthAccount>,
    ) -> Result<OAuthAccount, AuthError> {
        match crate::database_hooks::current_transaction() {
            Some(transaction) => {
                let DatabaseRecord::Account(account) = transaction
                    .create(crate::DatabaseCreateOperation::Account(account))
                    .await?
                else {
                    unreachable!("transaction create preserves its model")
                };
                Ok(account)
            }
            None => self.store.link_oauth_account(account).await,
        }
    }

    async fn write_oauth_account_update(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError> {
        match crate::database_hooks::current_transaction() {
            Some(transaction) => {
                let DatabaseRecord::Account(account) = transaction
                    .update(DatabaseRecord::Account(account))
                    .await?
                else {
                    unreachable!("transaction update preserves its model")
                };
                Ok(account)
            }
            None => self.store.update_oauth_account_tokens(account).await,
        }
    }
}

fn ensure_account_binding(
    policy: &OAuthSignInPolicy,
    account: &OAuthAccount,
    user_id: &str,
    user_info: &OAuthUserInfo,
) -> Result<(), AuthError> {
    if policy.require_exact_account_binding
        && (account.issuer != user_info.issuer
            || account.account_id != user_info.account_id
            || account.provider_id != policy.provider_id
            || account.user_id != user_id)
    {
        return Err(sso_conflict(
            "account_hook_binding_conflict",
            "Account hook changed the selected authentication binding",
        ));
    }
    Ok(())
}
