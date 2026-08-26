use super::{AuthService, SignInResult, email_password::normalize_email};
use crate::{
    AnonymousLinkAccount, AnonymousPlugin, AnonymousPluginConfig, AnonymousSignInContext,
    AuthError, AuthUser, AuthenticationMethod, SessionWithUser,
};
use chrono::Utc;

impl AuthService {
    pub async fn sign_in_anonymous(
        &self,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let config = self
            .plugins
            .find::<AnonymousPlugin>()
            .ok_or(AuthError::NotFound)?
            .config
            .clone();
        self.sign_in_anonymous_with(
            &config,
            AnonymousSignInContext {
                origin: None,
                ip_address,
                user_agent,
            },
        )
        .await
    }

    pub(crate) async fn sign_in_anonymous_with(
        &self,
        config: &AnonymousPluginConfig,
        context: AnonymousSignInContext,
    ) -> Result<SignInResult, AuthError> {
        let now = Utc::now();
        let email_entropy = crate::generate_database_id(crate::DatabaseIdGenerationSize::Omitted)
            .expect("the omitted Better Auth ID size is valid");
        let email = anonymous_email(config, &email_entropy).await?;
        let name = match &config.generate_name {
            Some(generator) => generator.generate(&context).await?,
            None => "Anonymous".into(),
        };
        let user = self
            .prepare_user_create(AuthUser {
                id: String::new(),
                username: None,
                display_username: None,
                name,
                email,
                email_verified: false,
                image: None,
                additional_fields: serde_json::Map::new(),
                role: self.default_user_role(),
                is_anonymous: true,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            })
            .await?;
        let user = self
            .store
            .create_anonymous_user(user)
            .await
            .map_err(|_| AuthError::AnonymousUserCreationFailed)?;
        self.finish_user_create(&user).await?;
        let result = match self
            .create_session(
                user.clone(),
                AuthenticationMethod::Anonymous,
                None,
                context.ip_address,
                context.user_agent,
            )
            .await
        {
            Ok(result) => result,
            Err(_) => {
                let _ = self.store.delete_user(&user.id).await;
                return Err(AuthError::AnonymousSessionCreationFailed);
            }
        };
        Ok(result)
    }

    pub async fn delete_anonymous_user(&self, session: &SessionWithUser) -> Result<(), AuthError> {
        let config = self
            .plugins
            .find::<AnonymousPlugin>()
            .ok_or(AuthError::NotFound)?
            .config
            .clone();
        self.delete_anonymous_user_with(&config, session).await
    }

    pub(crate) async fn delete_anonymous_user_with(
        &self,
        config: &AnonymousPluginConfig,
        session: &SessionWithUser,
    ) -> Result<(), AuthError> {
        if config.disable_delete_anonymous_user {
            return Err(AuthError::AnonymousUserDeletionDisabled);
        }
        if !session.user.is_anonymous {
            return Err(AuthError::UserIsNotAnonymous);
        }
        self.delete_user_sessions_with_hooks(&session.user.id)
            .await
            .map_err(|_| AuthError::AnonymousUserSessionDeletionFailed)?;
        self.store
            .delete_user(&session.user.id)
            .await
            .map_err(|_| AuthError::AnonymousUserDeletionFailed)
    }

    pub(crate) async fn complete_anonymous_upgrade(
        &self,
        source: &SessionWithUser,
        result: &SignInResult,
    ) -> Result<(), AuthError> {
        if !source.user.is_anonymous
            || result.session.user.is_anonymous
            || source.user.id == result.session.user.id
        {
            return Ok(());
        }
        if self.is_guest_capability_session(&source.session.id).await {
            return Ok(());
        }
        let Some(plugin) = self.plugins.find::<AnonymousPlugin>() else {
            return Ok(());
        };
        let callback_result = match &plugin.config.on_link_account {
            Some(callback) => {
                callback
                    .call(AnonymousLinkAccount {
                        anonymous_user: source.clone(),
                        new_user: result.session.clone(),
                    })
                    .await
            }
            None => Ok(()),
        };
        callback_result?;
        if !plugin.config.disable_delete_anonymous_user {
            self.store
                .delete_user(&source.user.id)
                .await
                .map_err(|_| AuthError::AnonymousUserDeletionFailed)?;
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn anonymous_upgrade_source(
        &self,
        user_id: Option<String>,
    ) -> Result<Option<SessionWithUser>, AuthError> {
        let Some(user_id) = user_id else {
            return Ok(None);
        };
        if self.plugins.find::<AnonymousPlugin>().is_none() {
            return Ok(None);
        }
        let Some(user) = self.store.find_user_by_id(&user_id).await? else {
            return Ok(None);
        };
        if !user.is_anonymous {
            return Ok(None);
        }
        let session = self
            .store
            .list_sessions(&user_id)
            .await?
            .into_iter()
            .find(|session| session.expires_at > Utc::now());
        Ok(session.map(|session| SessionWithUser { session, user }))
    }
}

async fn anonymous_email(config: &AnonymousPluginConfig, id: &str) -> Result<String, AuthError> {
    let email = match &config.generate_random_email {
        Some(generator) => generator.generate().await?,
        None => match &config.email_domain_name {
            Some(domain) => format!("temp-{id}@{domain}"),
            None => format!("temp@{id}.com"),
        },
    };
    normalize_email(&email).map_err(|_| AuthError::AnonymousInvalidEmail)
}
