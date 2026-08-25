use super::support::{Call, LifecycleClient, context, invoke_after_update, plugin, user};
use lucid_auth::{CommetCustomerUpdate, CommetProviderError};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn update_targets_only_the_first_customer_with_email_and_name() {
    let client = Arc::new(LifecycleClient::default());
    client.set_customers(json!({
        "data": [
            {"id": "customer_first"},
            {"id": "customer_second"}
        ]
    }));
    let plugin = plugin(client.clone(), true, None);
    let mut user = user(false);
    user.email = "new@example.com".into();
    user.name = "Updated Name".into();

    invoke_after_update(&plugin, &user, &context())
        .await
        .unwrap();

    assert_eq!(
        client.calls(),
        [
            Call::List(user.id.to_string()),
            Call::Update(
                "customer_first".into(),
                CommetCustomerUpdate {
                    email: Some("new@example.com".into()),
                    full_name: Some("Updated Name".into()),
                },
            ),
        ]
    );
}

#[tokio::test]
async fn update_without_an_existing_customer_stops_after_lookup() {
    let client = Arc::new(LifecycleClient::default());
    let plugin = plugin(client.clone(), true, None);
    let user = user(false);

    invoke_after_update(&plugin, &user, &context())
        .await
        .unwrap();

    assert_eq!(client.calls(), [Call::List(user.id.to_string())]);
}

#[tokio::test]
async fn update_preserves_an_empty_name_instead_of_treating_it_as_nullish() {
    let client = Arc::new(LifecycleClient::default());
    client.set_customers(json!({"data": [{"id": "customer_first"}]}));
    let plugin = plugin(client.clone(), true, None);
    let mut user = user(false);
    user.name.clear();

    invoke_after_update(&plugin, &user, &context())
        .await
        .unwrap();

    assert!(matches!(
        client.calls().as_slice(),
        [Call::List(_), Call::Update(_, CommetCustomerUpdate { full_name: Some(name), .. })]
            if name.is_empty()
    ));
}

#[tokio::test]
async fn list_and_update_failures_are_suppressed() {
    let list_client = Arc::new(LifecycleClient::default());
    list_client.fail_list(CommetProviderError::new("lookup unavailable"));
    invoke_after_update(
        &plugin(list_client.clone(), true, None),
        &user(false),
        &context(),
    )
    .await
    .unwrap();
    assert!(matches!(list_client.calls().as_slice(), [Call::List(_)]));

    let update_client = Arc::new(LifecycleClient::default());
    update_client.set_customers(json!({"data": [{"id": "customer_first"}]}));
    update_client.fail_update(CommetProviderError::new("update unavailable"));
    invoke_after_update(
        &plugin(update_client.clone(), true, None),
        &user(false),
        &context(),
    )
    .await
    .unwrap();
    assert!(matches!(
        update_client.calls().as_slice(),
        [Call::List(_), Call::Update(customer_id, _)] if customer_id == "customer_first"
    ));
}
