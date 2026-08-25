mod create;
mod update;

use super::CommetPlugin;
use crate::{AuthError, BeforeDatabaseHook, DatabaseHookContext, DatabaseHooks, DatabaseRecord};

#[async_trait::async_trait]
impl DatabaseHooks for CommetPlugin {
    async fn before_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseHook, AuthError> {
        if let DatabaseRecord::User(user) = record {
            create::before(self, user, context).await?;
        }
        Ok(BeforeDatabaseHook::Continue)
    }

    async fn after_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if let DatabaseRecord::User(user) = record {
            create::after(self, user, context).await?;
        }
        Ok(())
    }

    async fn after_update(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if let DatabaseRecord::User(user) = record {
            update::after(self, user, context).await;
        }
        Ok(())
    }
}

fn enabled(plugin: &CommetPlugin, context: &DatabaseHookContext) -> bool {
    plugin.options.create_customer_on_sign_up && context.request.is_some()
}
