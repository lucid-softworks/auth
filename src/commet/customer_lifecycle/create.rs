use super::enabled;
use crate::{
    AuthError, AuthUser, DatabaseHookContext, PluginApiError,
    commet::{
        CommetCustomerCreate, CommetCustomerCreateParams, CommetCustomerParamsError, CommetPlugin,
        CommetProviderError,
    },
};
use serde_json::Value;

pub(super) async fn before(
    plugin: &CommetPlugin,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    if !enabled(plugin, context) {
        return Ok(());
    }
    let result = before_inner(plugin, user, context).await;
    match result {
        Ok(()) => Ok(()),
        Err(CreateError::Api(error)) => Err(error.into()),
        Err(CreateError::Message(message)) => Err(PluginApiError::new(
            500,
            "INTERNAL_SERVER_ERROR",
            format!("Commet customer creation failed: {message}"),
        )
        .into()),
        Err(CreateError::Opaque) => Err(PluginApiError::new(
            500,
            "INTERNAL_SERVER_ERROR",
            "Commet customer creation failed",
        )
        .into()),
    }
}

async fn before_inner(
    plugin: &CommetPlugin,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<(), CreateError> {
    let request = context
        .request
        .as_ref()
        .expect("enabled hook has a request");
    let params = match &plugin.options.get_customer_create_params {
        Some(provider) => provider.params(user, request).await?,
        None => CommetCustomerCreateParams::default(),
    };
    if user.email.is_empty() {
        return Err(CreateError::Api(PluginApiError::new(
            400,
            "BAD_REQUEST",
            "An email is required to create a customer",
        )));
    }
    let customers = plugin
        .options
        .client
        .list_customers(&user.id.to_string())
        .await?;
    if first_customer(&customers).is_some() {
        return Ok(());
    }
    plugin
        .options
        .client
        .create_customer(CommetCustomerCreate {
            email: user.email.clone(),
            id: Some(user.id.to_string()),
            full_name: params.full_name.or_else(|| Some(user.name.clone())),
            metadata: params.metadata.map(Value::Object),
        })
        .await?;
    Ok(())
}

pub(super) async fn after(
    plugin: &CommetPlugin,
    user: &AuthUser,
    context: &DatabaseHookContext,
) -> Result<(), AuthError> {
    if !enabled(plugin, context) {
        return Ok(());
    }
    plugin
        .options
        .client
        .create_customer(CommetCustomerCreate {
            email: user.email.clone(),
            id: Some(user.id.to_string()),
            full_name: None,
            metadata: None,
        })
        .await
        .map(|_| ())
        .map_err(after_error)
}

fn after_error(error: CommetProviderError) -> AuthError {
    let message = match error {
        CommetProviderError::Opaque => "Commet customer link failed".to_owned(),
        error => format!("Commet customer link failed: {error}"),
    };
    PluginApiError::new(500, "INTERNAL_SERVER_ERROR", message).into()
}

pub(super) fn first_customer(value: &Value) -> Option<Value> {
    let data = value.get("data")?;
    let first = match data {
        Value::Array(values) => values.first().cloned(),
        Value::Object(values) => values.get("0").cloned(),
        Value::String(value) => value
            .chars()
            .next()
            .map(|value| Value::String(value.into())),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }?;
    javascript_truthy(&first).then_some(first)
}

fn javascript_truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Bool(true) | Value::Array(_) | Value::Object(_) => true,
    }
}

enum CreateError {
    Api(PluginApiError),
    Message(String),
    Opaque,
}

impl From<CommetCustomerParamsError> for CreateError {
    fn from(error: CommetCustomerParamsError) -> Self {
        match error {
            CommetCustomerParamsError::Api(error) => Self::Api(error),
            CommetCustomerParamsError::Message(message) => Self::Message(message),
            CommetCustomerParamsError::Opaque => Self::Opaque,
        }
    }
}

impl From<CommetProviderError> for CreateError {
    fn from(error: CommetProviderError) -> Self {
        match error {
            CommetProviderError::Api(error) => Self::Api(error),
            CommetProviderError::Opaque => Self::Opaque,
            error => Self::Message(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::first_customer;
    use serde_json::json;

    #[test]
    fn first_customer_matches_optional_indexing_and_javascript_truthiness() {
        for response in [
            json!({}),
            json!({"data": []}),
            json!({"data": [null]}),
            json!({"data": [false]}),
            json!({"data": [0]}),
            json!({"data": [""]}),
            json!({"data": {"0": null}}),
        ] {
            assert!(first_customer(&response).is_none(), "{response}");
        }
        for response in [
            json!({"data": [{}]}),
            json!({"data": [true]}),
            json!({"data": [1]}),
            json!({"data": ["customer"]}),
            json!({"data": {"0": {"id": "cus_1"}}}),
            json!({"data": "customer"}),
        ] {
            assert!(first_customer(&response).is_some(), "{response}");
        }
    }
}
