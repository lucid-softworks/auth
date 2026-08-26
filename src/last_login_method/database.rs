use super::{LastLoginMethodPlugin, context::resolve_method};
use crate::{
    AuthError, BeforeDatabaseCreateHook, DatabaseCreatePatch, DatabaseCreateRecord,
    DatabaseHookContext, DatabaseHooks, DatabaseModel, DatabaseRecord,
};
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
impl DatabaseHooks for LastLoginMethodPlugin {
    async fn before_create(
        &self,
        record: &DatabaseCreateRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        if record.model() != DatabaseModel::User {
            return Ok(BeforeDatabaseCreateHook::Continue);
        }
        let Some(request) = context.request.as_ref() else {
            return Ok(BeforeDatabaseCreateHook::Continue);
        };
        let resolve_context = super::LastLoginMethodContext::from_database_request(request);
        let Some(method) = resolve_method(
            self.config.custom_resolve_method.as_deref(),
            &resolve_context,
        )?
        .filter(|method| !method.is_empty()) else {
            return Ok(BeforeDatabaseCreateHook::Continue);
        };
        Ok(BeforeDatabaseCreateHook::Merge(
            DatabaseCreatePatch::new().with_field("lastLoginMethod", Value::String(method)),
        ))
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
        .update_last_login_method(&session.user_id, method)
        .await
    {
        eprintln!("Failed to update lastLoginMethod: {error}");
    }
    Ok(())
}
