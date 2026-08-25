mod create;
mod delete;
#[cfg(test)]
mod test_support;
mod update;

use super::PolarPlugin;
use crate::{AuthError, BeforeDatabaseHook, DatabaseHookContext, DatabaseHooks, DatabaseRecord};

#[async_trait::async_trait]
impl DatabaseHooks for PolarPlugin {
    async fn before_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseHook, AuthError> {
        if let DatabaseRecord::User(user) = record {
            create::before(&self.options, user, context).await?;
        }
        Ok(BeforeDatabaseHook::Continue)
    }

    async fn after_create(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if let DatabaseRecord::User(user) = record {
            create::after(&self.options, user, context).await?;
        }
        Ok(())
    }

    async fn after_update(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if let DatabaseRecord::User(user) = record {
            update::after(&self.options, user, context).await;
        }
        Ok(())
    }

    async fn after_delete(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if let DatabaseRecord::User(user) = record {
            delete::after(&self.options, user, context).await;
        }
        Ok(())
    }
}

pub(super) fn enabled(
    options: &super::PolarOptions,
    user: &crate::AuthUser,
    context: &DatabaseHookContext,
) -> bool {
    options.create_customer_on_sign_up && context.request.is_some() && !user.is_anonymous
}
