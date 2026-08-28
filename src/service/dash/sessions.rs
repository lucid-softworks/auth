use super::*;

impl AuthService {
    pub(crate) async fn dash_set_password(
        &self,
        user_id: &str,
        password: String,
    ) -> Result<(), AuthError> {
        self.set_password_hash_with_database_id(user_id, self.hash_password(password).await?)
            .await?;
        self.plugins
            .password_credential_changed(&PasswordCredentialChanged {
                user_id: user_id.to_owned(),
                source: PasswordCredentialSource::AdministratorReset,
            })
            .await
    }

    pub(crate) async fn dash_unlink_account(
        &self,
        user_id: &str,
        provider_id: &str,
        account_id: &str,
    ) -> Result<(), AuthError> {
        let accounts = self.store.list_user_accounts(user_id).await?;
        if accounts.len() == 1 && !self.config.account.account_linking.allow_unlinking_all {
            return Err(AuthError::InvalidRequest(
                "Cannot unlink the last account. This would lock the user out.".into(),
            ));
        }
        let account = accounts
            .iter()
            .find(|account| account.provider_id == provider_id && account.id == account_id)
            .ok_or(AuthError::NotFound)?;
        match self
            .store
            .delete_user_account(user_id, &account.id, true)
            .await?
        {
            crate::AccountDeleteOutcome::Deleted => Ok(()),
            crate::AccountDeleteOutcome::NotFound => Err(AuthError::NotFound),
            crate::AccountDeleteOutcome::LastAccount => Err(AuthError::InvalidRequest(
                "Cannot unlink the last account. This would lock the user out.".into(),
            )),
        }
    }

    pub(crate) async fn dash_revoke_owned_session(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> Result<(), AuthError> {
        let found = self
            .store
            .list_sessions(user_id)
            .await?
            .into_iter()
            .find(|session| session.id == session_id || session.token == session_id)
            .ok_or(AuthError::NotFound)?;
        self.delete_session_id_with_hooks(&found.id).await
    }

    pub(crate) async fn dash_revoke_all_sessions(&self, user_id: &str) -> Result<(), AuthError> {
        self.delete_user_sessions_with_hooks(user_id).await
    }

    pub(crate) async fn dash_impersonate_user(
        &self,
        user_id: &str,
        impersonated_by: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let user = self.dash_find_user(user_id).await?;
        self.create_session_until(
            user,
            None,
            impersonated_by,
            Some(Utc::now() + chrono::Duration::minutes(10)),
            None,
            None,
        )
        .await
    }

    pub(crate) async fn dash_ban_user(
        &self,
        user_id: &str,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        delete_sessions: bool,
    ) -> Result<(), AuthError> {
        self.dash_find_user(user_id).await?;
        let updated = self
            .store
            .update_user_ban(user_id, true, reason, expires_at)
            .await?;
        self.after_database_update(&crate::DatabaseRecord::User(updated))
            .await?;
        if delete_sessions {
            self.delete_user_sessions_with_hooks(user_id).await?;
        }
        Ok(())
    }

    pub(crate) async fn dash_unban_user(&self, user_id: &str) -> Result<(), AuthError> {
        self.dash_find_user(user_id).await?;
        let updated = self
            .store
            .update_user_ban(user_id, false, None, None)
            .await?;
        self.after_database_update(&crate::DatabaseRecord::User(updated))
            .await
    }

    pub(crate) async fn dash_send_verification_email(
        &self,
        user_id: &str,
        callback_url: &str,
    ) -> Result<(), AuthError> {
        let user = self.dash_find_user(user_id).await?;
        if user.email_verified {
            return Err(AuthError::EmailAlreadyVerified);
        }
        self.deliver_verification_email(user, Some(callback_url))
            .await
    }

    pub(crate) fn dash_verification_email_enabled(&self) -> bool {
        self.config.email_verification.sender.is_some()
    }

    pub(crate) async fn dash_send_create_verification_email(
        &self,
        user: AuthUser,
    ) -> Result<(), AuthError> {
        if !self.dash_verification_email_enabled() {
            return Ok(());
        }
        self.deliver_verification_email(user, None).await
    }

    pub(crate) async fn dash_send_reset_password_email(
        &self,
        user_id: &str,
        callback_url: &str,
    ) -> Result<(), AuthError> {
        let user = self.dash_find_user(user_id).await?;
        self.request_password_reset(&user.email, Some(callback_url))
            .await
    }
}
