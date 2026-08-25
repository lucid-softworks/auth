use super::value::{
    invalid, object_member, optional_string, parsed_truthy_date, required_object_like_member,
    truthy, truthy_member, truthy_string,
};
use crate::creem::{CreemPersistenceError, CreemStore, CreemSubscription, CreemSubscriptionPatch};
use serde_json::{Map, Value};

pub(super) async fn persist(
    store: &dyn CreemStore,
    checkout: &Map<String, Value>,
) -> Result<(), CreemPersistenceError> {
    let Some(customer_id) = nested_truthy_string(checkout.get("customer"), "id", "customer.id")?
    else {
        return Ok(());
    };
    let Some(reference_id) = nested_truthy_string(
        checkout.get("metadata"),
        "referenceId",
        "metadata.referenceId",
    )?
    else {
        return Ok(());
    };

    link_customer(store, &reference_id, &customer_id).await;

    let Some(subscription) = truthy_member(checkout, "subscription") else {
        return Ok(());
    };
    let Some(order) = truthy_member(checkout, "order") else {
        return Ok(());
    };
    let product_id = product_id(checkout)?;
    let Some(subscription_id) =
        truthy_string(object_member(subscription, "id"), "subscription.id")?
    else {
        return Ok(());
    };
    let order_id = order_id(order)?;
    let status = optional_string(object_member(subscription, "status"), "subscription.status")?;
    let period_start = parsed_truthy_date(
        object_member(subscription, "current_period_start_date"),
        "subscription.current_period_start_date",
    )?;
    let period_end = parsed_truthy_date(
        object_member(subscription, "current_period_end_date"),
        "subscription.current_period_end_date",
    )?;

    let patch = CreemSubscriptionPatch {
        product_id: Some(product_id.clone()),
        reference_id: Some(reference_id.clone()),
        status: status.clone(),
        creem_customer_id: Some(Some(customer_id.clone())),
        creem_subscription_id: Some(Some(subscription_id.clone())),
        creem_order_id: order_id.clone(),
        period_start: period_start.map(Some),
        period_end: period_end.map(Some),
    };
    if let Some(existing) = store
        .find_subscription_by_creem_id(&subscription_id)
        .await
        .map_err(store_error)?
    {
        store
            .update_subscription(existing.id, patch)
            .await
            .map_err(store_error)?;
    } else {
        let mut created = CreemSubscription::new(product_id, reference_id);
        created.creem_customer_id = Some(customer_id);
        created.creem_subscription_id = Some(subscription_id);
        created.creem_order_id = order_id.flatten();
        if let Some(status) = status {
            created.status = status;
        }
        created.period_start = period_start;
        created.period_end = period_end;
        store
            .create_subscription(created)
            .await
            .map_err(store_error)?;
    }
    Ok(())
}

async fn link_customer(store: &dyn CreemStore, reference_id: &str, customer_id: &str) {
    let result = async {
        let user = store.find_user(reference_id).await?;
        if user
            .as_ref()
            .is_some_and(|user| !user.creem_customer_id.as_ref().is_some_and(truthy))
        {
            store
                .set_user_customer_id(reference_id, customer_id)
                .await?;
        }
        Ok::<(), crate::creem::CreemStoreError>(())
    }
    .await;
    if let Err(error) = result {
        tracing::error!(message = %error, "Creem customer-link persistence failed");
    }
}

fn nested_truthy_string(
    container: Option<&Value>,
    member: &str,
    field: &str,
) -> Result<Option<String>, CreemPersistenceError> {
    truthy_string(
        container.and_then(|value| object_member(value, member)),
        field,
    )
}

fn product_id(checkout: &Map<String, Value>) -> Result<String, CreemPersistenceError> {
    let id = required_object_like_member(checkout, "product", "id")?;
    match id.filter(|value| truthy(value)) {
        None => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(invalid("product.id")),
    }
}

fn order_id(order: &Value) -> Result<Option<Option<String>>, CreemPersistenceError> {
    let value = if order.is_object() {
        let Some(value) = object_member(order, "id") else {
            return Ok(None);
        };
        value
    } else {
        order
    };
    match value {
        Value::Null => Ok(Some(None)),
        Value::String(value) => Ok(Some(Some(value.clone()))),
        _ => Err(invalid("order.id")),
    }
}

fn store_error(error: crate::creem::CreemStoreError) -> CreemPersistenceError {
    CreemPersistenceError::new(error.to_string())
}
