use super::{LastLoginMethodPlugin, context::resolve_method};
use crate::{AuthError, BeforeDatabaseHook, DatabaseHookContext, DatabaseHooks, DatabaseRecord};
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
impl DatabaseHooks for LastLoginMethodPlugin {
    async fn before_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseHook, AuthError> {
        let DatabaseRecord::User(user) = record else {
            return Ok(BeforeDatabaseHook::Continue);
        };
        let Some(request) = context.request.as_ref() else {
            return Ok(BeforeDatabaseHook::Continue);
        };
        let resolve_context = super::LastLoginMethodContext::from_database_request(request);
        let Some(method) = resolve_method(
            self.config.custom_resolve_method.as_deref(),
            &resolve_context,
        )?
        .filter(|method| !method.is_empty()) else {
            return Ok(BeforeDatabaseHook::Continue);
        };
        let mut user = user.clone();
        user.additional_fields
            .insert("lastLoginMethod".into(), Value::String(method));
        Ok(BeforeDatabaseHook::replace(DatabaseRecord::User(user)))
    }
}

pub(super) async fn after_create(
    plugin: &LastLoginMethodPlugin,
    service: &crate::AuthService,
    record: &DatabaseRecord,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    if !plugin.config.store_in_database {
        return Ok(());
    }
    let DatabaseRecord::Session(session) = record else {
        return Ok(());
    };
    let Some(request) = context.request.as_ref() else {
        return Ok(());
    };
    let resolve_context = super::LastLoginMethodContext::from_database_request(request);
    let Some(method) = resolve_method(
        plugin.config.custom_resolve_method.as_deref(),
        &resolve_context,
    )?
    .filter(|method| !method.is_empty()) else {
        return Ok(());
    };
    if let Err(error) = service
        .update_last_login_method(session.user_id, method)
        .await
    {
        eprintln!("Failed to update lastLoginMethod: {error}");
    }
    Ok(())
}
