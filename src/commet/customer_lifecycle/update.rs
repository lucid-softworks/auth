use super::{create::first_customer, enabled};
use crate::{
    AuthUser, DatabaseHookContext,
    commet::{CommetCustomerUpdate, CommetPlugin},
};

pub(super) async fn after(plugin: &CommetPlugin, user: &AuthUser, context: &DatabaseHookContext) {
    if !enabled(plugin, context) {
        return;
    }
    let result = async {
        let customers = plugin
            .options
            .client
            .list_customers(&user.id.to_string())
            .await?;
        let Some(customer_id) = first_customer(&customers).and_then(|customer| {
            customer
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        }) else {
            return Ok(());
        };
        plugin
            .options
            .client
            .update_customer(
                &customer_id,
                CommetCustomerUpdate {
                    email: Some(user.email.clone()),
                    full_name: Some(user.name.clone()),
                },
            )
            .await?;
        Ok::<(), crate::CommetProviderError>(())
    }
    .await;
    if let Err(error) = result {
        match error {
            crate::CommetProviderError::Opaque => {
                tracing::error!("Commet customer update failed");
            }
            error => tracing::error!("Commet customer update failed: {error}"),
        }
    }
}
