mod checkout;
mod created;
mod deleted;
mod support;
mod updated;

use crate::stripe::{StripeEvent, StripeOptions, StripeStore};
use support::*;

pub(super) async fn run(
    options: &StripeOptions,
    store: &dyn StripeStore,
    event: &StripeEvent,
) -> Result<(), LifecycleError> {
    let context = LifecycleContext { options, store };
    match event.event_type.as_str() {
        "checkout.session.completed" => checkout::handle(context, event).await,
        "customer.subscription.created" => created::handle(context, event).await,
        "customer.subscription.updated" => updated::handle(context, event).await,
        "customer.subscription.deleted" => deleted::handle(context, event).await,
        _ => Ok(()),
    }
}
