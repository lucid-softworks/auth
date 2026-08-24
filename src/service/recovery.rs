use super::{AuthService, SignInResult, password::verify_password, random_token};
use crate::{
    AuthError, AuthenticationMethod, RecoveryCodeStatus, SensitiveOperation, SessionWithUser,
    StepUpAssurance, StepUpError, StepUpPolicyPlugin, StepUpSession, StepUpSessionProjection,
};
use chrono::Utc;
use serde_json::json;

impl AuthService {
    pub(crate) async fn step_up_session_projection(
        &self,
        session: &SessionWithUser,
    ) -> Result<StepUpSessionProjection, AuthError> {
        self.step_up_plugin()?.project_session(session).await
    }

    pub(crate) async fn generate_step_up_recovery_codes(
        &self,
        actor: &SessionWithUser,
        password: String,
    ) -> Result<Vec<String>, AuthError> {
        let plugin = self.step_up_plugin()?;
        require_step_up_account(plugin, actor)?;
        self.plugins
            .authorize_sensitive(&SensitiveOperation {
                session: actor,
                operation: "step-up-recovery-code-generation",
            })
            .await?;
        let password_hash = self
            .store
            .find_password_hash(actor.user.id)
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;
        if !verify_password(password, Some(password_hash)).await? {
            return Err(AuthError::InvalidPassword);
        }
        let codes: Vec<_> = (0..plugin.config.recovery_code_count)
            .map(|_| recovery_code())
            .collect();
        let hashes = codes
            .iter()
            .map(|code| self.recovery_code_hash(code))
            .collect();
        plugin
            .store
            .replace_step_up_recovery_codes(actor.user.id, hashes)
            .await?;
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "step_up.recovery_codes.generated",
            None,
            json!({ "count": codes.len() }),
        )
        .await;
        Ok(codes)
    }

    pub(crate) async fn step_up_recovery_code_status(
        &self,
        actor: &SessionWithUser,
    ) -> Result<RecoveryCodeStatus, AuthError> {
        let plugin = self.step_up_plugin()?;
        require_step_up_account(plugin, actor)?;
        Ok(RecoveryCodeStatus {
            remaining: plugin
                .store
                .step_up_recovery_code_count(actor.user.id)
                .await?,
        })
    }

    pub(crate) async fn verify_step_up_recovery_code(
        &self,
        actor: &SessionWithUser,
        code: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let plugin = self.step_up_plugin()?;
        require_step_up_account(plugin, actor)?;
        let (state, authenticated_at) = self
            .consume_step_up_recovery_code(plugin, actor, code)
            .await?;
        let result = self
            .create_session(
                actor.user.clone(),
                AuthenticationMethod::Extension,
                None,
                ip_address,
                user_agent,
            )
            .await?;
        plugin
            .store
            .upsert_step_up_session(StepUpSession {
                session_id: result.session.session.id,
                user_id: result.session.user.id,
                assurance: StepUpAssurance::Recovery,
                authenticated_at,
            })
            .await?;
        self.delete_session_id_with_hooks(actor.session.id).await?;
        plugin
            .store
            .delete_step_up_session(state.session_id)
            .await?;
        self.audit_recovery_use(plugin, actor, &result).await?;
        Ok(result)
    }

    async fn consume_step_up_recovery_code(
        &self,
        plugin: &StepUpPolicyPlugin,
        actor: &SessionWithUser,
        code: &str,
    ) -> Result<(StepUpSession, chrono::DateTime<Utc>), AuthError> {
        let state = plugin
            .store
            .find_step_up_session(actor.session.id)
            .await?
            .filter(|state| {
                state.user_id == actor.user.id && state.assurance == StepUpAssurance::PendingPasskey
            })
            .ok_or(AuthError::Forbidden)?;
        let limit_key = recovery_limit_key(actor.user.id);
        let now = Utc::now();
        let window = u64::try_from(plugin.config.recovery_rate_limit_window.num_seconds())
            .unwrap_or(u64::MAX);
        let outcome = self
            .store
            .consume_rate_limit(
                &limit_key,
                now,
                crate::RateLimitRule::new(window, plugin.config.recovery_rate_limit_max),
                window,
            )
            .await?;
        if !outcome.allowed {
            return Err(AuthError::RateLimited);
        }
        if plugin
            .store
            .step_up_recovery_code_count(actor.user.id)
            .await?
            == 0
        {
            return Err(StepUpError::RecoveryCodesNotEnabled.into());
        }
        let valid = plugin
            .store
            .consume_step_up_recovery_code(actor.user.id, &self.recovery_code_hash(code))
            .await?;
        if !valid {
            return Err(StepUpError::InvalidRecoveryCode.into());
        }
        Ok((state, now))
    }

    async fn audit_recovery_use(
        &self,
        plugin: &StepUpPolicyPlugin,
        actor: &SessionWithUser,
        result: &SignInResult,
    ) -> Result<(), AuthError> {
        let remaining = plugin
            .store
            .step_up_recovery_code_count(actor.user.id)
            .await?;
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "step_up.recovery_code.used",
            Some(result.session.session.id.to_string()),
            json!({ "remaining": remaining }),
        )
        .await;
        Ok(())
    }

    fn step_up_plugin(&self) -> Result<&StepUpPolicyPlugin, AuthError> {
        self.plugins.find().ok_or_else(|| {
            AuthError::InvalidConfiguration("step-up policy plugin is disabled".into())
        })
    }

    fn recovery_code_hash(&self, code: &str) -> String {
        self.sign(normalize_recovery_code(code).as_bytes())
    }
}

fn require_step_up_account(
    plugin: &StepUpPolicyPlugin,
    session: &SessionWithUser,
) -> Result<(), AuthError> {
    if session.user.is_anonymous
        || session.session.actor_user_id.is_some()
        || !plugin.requires(&session.user.role)
    {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

fn recovery_code() -> String {
    let raw: String = random_token().chars().take(10).collect();
    format!("{}-{}", &raw[..5], &raw[5..])
}

fn normalize_recovery_code(code: &str) -> String {
    code.trim()
        .chars()
        .filter(|character| *character != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

fn recovery_limit_key(user_id: uuid::Uuid) -> String {
    format!("step-up-recovery:{user_id}")
}
