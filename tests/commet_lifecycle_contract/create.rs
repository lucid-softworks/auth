use super::support::{
    Call, CustomerParams, LifecycleClient, assert_api_error, context, invoke_after_create,
    invoke_after_update, invoke_before_create, plugin, user,
};
use lucid_auth::{
    BeforeDatabaseCreateHook, CommetCustomerCreate, CommetCustomerCreateParams,
    CommetCustomerParamsError, CommetProviderError, DatabaseHookContext, PluginApiError,
};
use serde_json::{Value, json};
use std::sync::Arc;

fn metadata(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[tokio::test]
async fn disabled_and_contextless_hooks_skip_side_effects_but_anonymous_users_do_not() {
    let disabled_client = Arc::new(LifecycleClient::default());
    let disabled = plugin(disabled_client.clone(), false, None);
    let ordinary_user = user(false);
    invoke_before_create(&disabled, &ordinary_user, &context())
        .await
        .unwrap();
    invoke_after_create(&disabled, &ordinary_user, &context())
        .await
        .unwrap();
    invoke_after_update(&disabled, &ordinary_user, &context())
        .await
        .unwrap();
    assert!(disabled_client.calls().is_empty());

    let contextless_client = Arc::new(LifecycleClient::default());
    let contextless = plugin(contextless_client.clone(), true, None);
    invoke_before_create(
        &contextless,
        &ordinary_user,
        &DatabaseHookContext::default(),
    )
    .await
    .unwrap();
    invoke_after_create(
        &contextless,
        &ordinary_user,
        &DatabaseHookContext::default(),
    )
    .await
    .unwrap();
    invoke_after_update(
        &contextless,
        &ordinary_user,
        &DatabaseHookContext::default(),
    )
    .await
    .unwrap();
    assert!(contextless_client.calls().is_empty());

    let anonymous_client = Arc::new(LifecycleClient::default());
    let anonymous = user(true);
    let anonymous_plugin = plugin(anonymous_client.clone(), true, None);
    invoke_before_create(&anonymous_plugin, &anonymous, &context())
        .await
        .unwrap();
    assert_eq!(
        anonymous_client.calls(),
        [Call::Create(CommetCustomerCreate {
            email: anonymous.email.clone(),
            id: None,
            full_name: Some(anonymous.name.clone()),
            metadata: None,
        })]
    );
}

#[tokio::test]
async fn callback_runs_before_email_validation_and_receives_the_request() {
    let client = Arc::new(LifecycleClient::default());
    let params = CustomerParams::new(Ok(CommetCustomerCreateParams {
        domain: Some("ignored.example.test".into()),
        ..CommetCustomerCreateParams::default()
    }));
    let plugin = plugin(client.clone(), true, Some(params.clone()));
    let mut email_less = user(false);
    email_less.email.clear();
    email_less
        .additional_fields
        .insert("customDraft".into(), json!({ "nested": true }));
    let hook_context = context();

    let error = invoke_before_create(&plugin, &email_less, &hook_context)
        .await
        .unwrap_err();

    assert_api_error(
        error,
        400,
        "BAD_REQUEST",
        "An email is required to create a customer",
    );
    let calls = params.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.id, None);
    assert_eq!(calls[0].0.email, "");
    assert_eq!(calls[0].0.fields["customDraft"], json!({ "nested": true }));
    assert_eq!(calls[0].1, hook_context.request.unwrap());
    assert!(client.calls().is_empty());
}

#[tokio::test]
async fn callback_error_takes_precedence_over_missing_email() {
    let client = Arc::new(LifecycleClient::default());
    let params = CustomerParams::new(Err(CommetCustomerParamsError::Api(PluginApiError::new(
        409,
        "CONFLICT",
        "callback runs first",
    ))));
    let plugin = plugin(client.clone(), true, Some(params));
    let mut email_less = user(false);
    email_less.email.clear();

    let error = invoke_before_create(&plugin, &email_less, &context())
        .await
        .unwrap_err();

    assert_api_error(error, 409, "CONFLICT", "callback runs first");
    assert!(client.calls().is_empty());
}

#[tokio::test]
async fn before_then_after_performs_the_exact_double_create_and_ignores_domain() {
    let client = Arc::new(LifecycleClient::default());
    let custom_metadata = metadata(json!({
        "cohort": "contract",
        "nested": {"enabled": true},
        "weight": 3
    }));
    let params = CustomerParams::new(Ok(CommetCustomerCreateParams {
        full_name: Some("Custom Name".into()),
        domain: Some("intentionally-not-forwarded.test".into()),
        metadata: Some(custom_metadata.clone()),
    }));
    let plugin = plugin(client.clone(), true, Some(params));
    let user = user(false);

    assert_eq!(
        invoke_before_create(&plugin, &user, &context())
            .await
            .unwrap(),
        BeforeDatabaseCreateHook::Continue
    );
    invoke_after_create(&plugin, &user, &context())
        .await
        .unwrap();

    assert_eq!(
        client.calls(),
        [
            Call::Create(CommetCustomerCreate {
                email: user.email.clone(),
                id: None,
                full_name: Some("Custom Name".into()),
                metadata: Some(Value::Object(custom_metadata)),
            }),
            Call::Create(CommetCustomerCreate {
                email: user.email.clone(),
                id: Some(user.id.to_string()),
                full_name: None,
                metadata: None,
            }),
        ]
    );
}

#[tokio::test]
async fn nullish_custom_name_falls_back_to_user_name() {
    let client = Arc::new(LifecycleClient::default());
    let params = CustomerParams::new(Ok(CommetCustomerCreateParams::default()));
    let plugin = plugin(client.clone(), true, Some(params));
    let user = user(false);

    invoke_before_create(&plugin, &user, &context())
        .await
        .unwrap();

    let calls = client.calls();
    let [Call::Create(request)] = calls.as_slice() else {
        panic!("expected customer creation without an ID lookup");
    };
    assert_eq!(request.full_name.as_deref(), Some(user.name.as_str()));
}

#[tokio::test]
async fn idless_before_create_does_not_lookup_a_customer_by_a_fabricated_id() {
    let client = Arc::new(LifecycleClient::default());
    client.set_customers(json!({"data": [{"id": "customer_existing"}]}));
    let plugin = plugin(client.clone(), true, None);
    let user = user(false);

    invoke_before_create(&plugin, &user, &context())
        .await
        .unwrap();
    invoke_after_create(&plugin, &user, &context())
        .await
        .unwrap();

    assert_eq!(
        client.calls(),
        [
            Call::Create(CommetCustomerCreate {
                email: user.email.clone(),
                id: None,
                full_name: Some(user.name.clone()),
                metadata: None,
            }),
            Call::Create(CommetCustomerCreate {
                email: user.email.clone(),
                id: Some(user.id.to_string()),
                full_name: None,
                metadata: None,
            }),
        ]
    );
}

#[tokio::test]
async fn before_maps_callback_api_message_and_opaque_failures() {
    let user = user(false);

    let api_params = CustomerParams::new(Err(CommetCustomerParamsError::Api(PluginApiError::new(
        403,
        "FORBIDDEN",
        "callback policy",
    ))));
    let api_error = invoke_before_create(
        &plugin(Arc::new(LifecycleClient::default()), true, Some(api_params)),
        &user,
        &context(),
    )
    .await
    .unwrap_err();
    assert_api_error(api_error, 403, "FORBIDDEN", "callback policy");

    let message_params =
        CustomerParams::new(Err(CommetCustomerParamsError::message("callback detail")));
    let message_error = invoke_before_create(
        &plugin(
            Arc::new(LifecycleClient::default()),
            true,
            Some(message_params),
        ),
        &user,
        &context(),
    )
    .await
    .unwrap_err();
    assert_api_error(
        message_error,
        500,
        "INTERNAL_SERVER_ERROR",
        "Commet customer creation failed: callback detail",
    );

    let opaque_params = CustomerParams::new(Err(CommetCustomerParamsError::Opaque));
    let opaque_error = invoke_before_create(
        &plugin(
            Arc::new(LifecycleClient::default()),
            true,
            Some(opaque_params),
        ),
        &user,
        &context(),
    )
    .await
    .unwrap_err();
    assert_api_error(
        opaque_error,
        500,
        "INTERNAL_SERVER_ERROR",
        "Commet customer creation failed",
    );
}

#[tokio::test]
async fn before_maps_provider_api_message_and_opaque_failures() {
    let user = user(false);

    let api_client = Arc::new(LifecycleClient::default());
    api_client.fail_create(LifecycleClient::api_error("provider policy"));
    let provider_api_error =
        invoke_before_create(&plugin(api_client, true, None), &user, &context())
            .await
            .unwrap_err();
    assert_api_error(provider_api_error, 403, "FORBIDDEN", "provider policy");

    let ordinary_client = Arc::new(LifecycleClient::default());
    ordinary_client.fail_create(CommetProviderError::new("provider detail"));
    let ordinary_error =
        invoke_before_create(&plugin(ordinary_client, true, None), &user, &context())
            .await
            .unwrap_err();
    assert_api_error(
        ordinary_error,
        500,
        "INTERNAL_SERVER_ERROR",
        "Commet customer creation failed: provider detail",
    );

    let opaque_client = Arc::new(LifecycleClient::default());
    opaque_client.fail_create(CommetProviderError::opaque());
    let opaque_provider_error =
        invoke_before_create(&plugin(opaque_client, true, None), &user, &context())
            .await
            .unwrap_err();
    assert_api_error(
        opaque_provider_error,
        500,
        "INTERNAL_SERVER_ERROR",
        "Commet customer creation failed",
    );
}

#[tokio::test]
async fn after_wraps_provider_api_and_ordinary_errors_and_hides_opaque_failures() {
    let user = user(false);

    let api_client = Arc::new(LifecycleClient::default());
    api_client.fail_create(LifecycleClient::api_error("inner API error"));
    let api_error = invoke_after_create(&plugin(api_client, true, None), &user, &context())
        .await
        .unwrap_err();
    assert_api_error(
        api_error,
        500,
        "INTERNAL_SERVER_ERROR",
        "Commet customer link failed: inner API error",
    );

    let ordinary_client = Arc::new(LifecycleClient::default());
    ordinary_client.fail_create(CommetProviderError::new("provider detail"));
    let ordinary_error =
        invoke_after_create(&plugin(ordinary_client, true, None), &user, &context())
            .await
            .unwrap_err();
    assert_api_error(
        ordinary_error,
        500,
        "INTERNAL_SERVER_ERROR",
        "Commet customer link failed: provider detail",
    );

    let opaque_client = Arc::new(LifecycleClient::default());
    opaque_client.fail_create(CommetProviderError::opaque());
    let opaque_error = invoke_after_create(&plugin(opaque_client, true, None), &user, &context())
        .await
        .unwrap_err();
    assert_api_error(
        opaque_error,
        500,
        "INTERNAL_SERVER_ERROR",
        "Commet customer link failed",
    );
}
