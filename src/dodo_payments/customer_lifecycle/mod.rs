mod create;
mod support;
#[cfg(test)]
mod test_support;
mod update;

use super::DodoPaymentsPlugin;
use crate::{AuthError, DatabaseHookContext, DatabaseHooks, DatabaseRecord};

#[async_trait::async_trait]
impl DatabaseHooks for DodoPaymentsPlugin {
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

fn enabled(plugin: &DodoPaymentsPlugin, context: &DatabaseHookContext) -> bool {
    plugin.options.create_customer_on_sign_up && context.request.is_some()
}
