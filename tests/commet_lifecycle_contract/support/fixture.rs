use async_trait::async_trait;
use chrono::Utc;
use lucid_auth::{
    AuthError, AuthUser, BeforeDatabaseCreateHook, CommetCreateUser, CommetCustomerCreateParams,
    CommetCustomerParamsError, CommetCustomerParamsProvider, CommetOptions, CommetPlugin,
    DatabaseCreateRecord, DatabaseHookContext, DatabaseHookRequest, DatabaseHooks, DatabaseModel,
    DatabaseRecord, PluginApiError,
};
use std::sync::{Arc, Mutex};

use super::LifecycleClient;

pub(crate) struct CustomerParams {
    result: Result<CommetCustomerCreateParams, CommetCustomerParamsError>,
    calls: Mutex<Vec<(CommetCreateUser, DatabaseHookRequest)>>,
}

impl CustomerParams {
    pub(crate) fn new(
        result: Result<CommetCustomerCreateParams, CommetCustomerParamsError>,
    ) -> Arc<Self> {
        Arc::new(Self {
            result,
            calls: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn calls(&self) -> Vec<(CommetCreateUser, DatabaseHookRequest)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl CommetCustomerParamsProvider for CustomerParams {
    async fn params(
        &self,
        user: &CommetCreateUser,
        request: &DatabaseHookRequest,
    ) -> Result<CommetCustomerCreateParams, CommetCustomerParamsError> {
        self.calls
            .lock()
            .unwrap()
            .push((user.clone(), request.clone()));
        self.result.clone()
    }
}

pub(crate) fn plugin(
    client: Arc<LifecycleClient>,
    enabled: bool,
    params: Option<Arc<dyn CommetCustomerParamsProvider>>,
) -> CommetPlugin {
    let mut options = CommetOptions::new(client, Vec::new());
    options.create_customer_on_sign_up = enabled;
    options.get_customer_create_params = params;
    CommetPlugin::new(options)
}

pub(crate) fn user(is_anonymous: bool) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: uuid::Uuid::new_v4().to_string(),
        username: None,
        display_username: None,
        name: "User Name".into(),
        email: "user@example.com".into(),
        email_verified: false,
        image: None,
        additional_fields: Default::default(),
        role: "user".into(),
        is_anonymous,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn context() -> DatabaseHookContext {
    DatabaseHookContext {
        request: Some(DatabaseHookRequest {
            method: "POST".into(),
            path: "/api/auth/sign-up/email".into(),
            query: None,
            headers: Default::default(),
        }),
        creation_method: None,
        transaction: None,
    }
}

pub(crate) async fn invoke_before_create(
    plugin: &CommetPlugin,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<BeforeDatabaseCreateHook, AuthError> {
    let mut fields = serde_json::to_value(user)
        .expect("serialize user draft")
        .as_object()
        .expect("user draft object")
        .clone();
    fields.remove("id");
    plugin
        .before_create(
            &DatabaseCreateRecord::new(DatabaseModel::User, fields),
            context,
        )
        .await
}

pub(crate) async fn invoke_after_create(
    plugin: &CommetPlugin,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    plugin
        .after_create(&DatabaseRecord::User(user.clone()), context)
        .await
}

pub(crate) async fn invoke_after_update(
    plugin: &CommetPlugin,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    plugin
        .after_update(&DatabaseRecord::User(user.clone()), context)
        .await
}

pub(crate) fn assert_api_error(error: AuthError, status: u16, code: &str, message: &str) {
    let AuthError::PluginApi(PluginApiError {
        status: actual_status,
        code: actual_code,
        message: actual_message,
    }) = error
    else {
        panic!("expected plugin API error, got {error:?}");
    };
    assert_eq!(actual_status, status);
    assert_eq!(actual_code, code);
    assert_eq!(actual_message, message);
}
