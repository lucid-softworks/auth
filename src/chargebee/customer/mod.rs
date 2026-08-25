mod lifecycle;
#[cfg(feature = "axum")]
mod on_demand;
mod spread;

pub(crate) use lifecycle::{after_user_create, after_user_update, before_user_delete};
#[cfg(feature = "axum")]
pub(crate) use on_demand::{organization_customer_id, user_customer_id};
pub(crate) use spread::merge_object_spread;
#[cfg(feature = "axum")]
pub(crate) use spread::metadata_customer_type;

use super::{ChargebeeCallbackContext, ChargebeeStore, ChargebeeUserSnapshot};
use crate::{AuthUser, DatabaseHookContext};

pub(crate) async fn user_snapshot(
    store: &dyn ChargebeeStore,
    user: &AuthUser,
) -> ChargebeeUserSnapshot {
    let customer_id = store.user_customer_id(user.id).await.ok().flatten();
    ChargebeeUserSnapshot {
        id: user.id.to_string(),
        name: user.name.clone(),
        email: user.email.clone(),
        email_verified: user.email_verified,
        chargebee_customer_id: customer_id,
        additional_fields: user.additional_fields.clone(),
    }
}

pub(crate) fn hook_context(context: &DatabaseHookContext) -> ChargebeeCallbackContext {
    context
        .request
        .as_ref()
        .map_or_else(ChargebeeCallbackContext::default, |request| {
            ChargebeeCallbackContext {
                method: Some(request.method.clone()),
                path: Some(request.path.clone()),
                query: request.query.clone(),
                headers: request.headers.clone(),
            }
        })
}
