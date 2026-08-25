use super::{merge_object_spread, metadata_customer_type};
use crate::chargebee::{
    ChargebeeApiError, ChargebeeCallbackContext, ChargebeeCustomerListRequest, ChargebeeErrorCode,
    ChargebeeOptions, ChargebeeOrganizationSnapshot, ChargebeeStore, ChargebeeUserSnapshot,
};
use serde_json::{Map, Value};
use uuid::Uuid;

pub(crate) async fn user_customer_id(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    user_id: Uuid,
    user: &ChargebeeUserSnapshot,
    metadata: Option<&serde_json::Map<String, Value>>,
    context: &ChargebeeCallbackContext,
) -> Result<String, ChargebeeApiError> {
    if let Some(customer_id) = &user.chargebee_customer_id {
        return Ok(customer_id.clone());
    }
    let result = async {
        let listed = options
            .client
            .list_customers(ChargebeeCustomerListRequest {
                email: Some(user.email.clone()),
                limit: Some(1),
            })
            .await
            .map_err(|error| error.message)?;
        let mut customer = listed.into_iter().find(|customer| {
            metadata_customer_type(customer.metadata.as_ref()) != Some("organization")
        });
        if customer.is_none() {
            let mut provider_metadata = Map::from_iter([
                ("userId".into(), Value::String(user.id.clone())),
                ("customerType".into(), Value::String("user".into())),
            ]);
            if let Some(metadata) = metadata {
                provider_metadata.extend(metadata.clone());
            }
            let mut request = Map::from_iter([
                ("email".into(), Value::String(user.email.clone())),
                ("meta_data".into(), Value::Object(provider_metadata)),
            ]);
            if let Some(provider) = &options.get_customer_create_params {
                let extra = provider
                    .params(user, Some(context))
                    .await
                    .map_err(|error| error.message)?;
                merge_object_spread(&mut request, extra);
            }
            customer = Some(
                options
                    .client
                    .create_customer(Value::Object(request))
                    .await
                    .map_err(|error| error.message)?,
            );
        }
        let customer = customer.expect("a listed or newly created customer exists");
        if let Some(winner) = store
            .user_customer_id(user_id)
            .await
            .map_err(|error| error.to_string())?
        {
            if let Err(error) = options.client.delete_customer(&customer.id).await {
                tracing::warn!(customer_id = %customer.id, %error, "Failed to clean up duplicate Chargebee customer");
            }
            return Ok(winner);
        }
        store
            .set_user_customer_id(user_id, Some(customer.id.clone()))
            .await
            .map_err(|error| error.to_string())?;
        Ok(customer.id)
    }
    .await;
    result.map_err(|error: String| {
        tracing::error!(%error, "Error creating customer");
        ChargebeeApiError::code(400, ChargebeeErrorCode::UnableToCreateCustomer)
    })
}

pub(crate) async fn organization_customer_id(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    organization_id: Uuid,
    organization: &ChargebeeOrganizationSnapshot,
    metadata: Option<&serde_json::Map<String, Value>>,
    context: &ChargebeeCallbackContext,
) -> Result<String, ChargebeeApiError> {
    if let Some(customer_id) = &organization.chargebee_customer_id {
        return Ok(customer_id.clone());
    }
    let result = async {
        let mut provider_metadata = Map::from_iter([
            (
                "organizationId".into(),
                Value::String(organization.id.clone()),
            ),
            (
                "customerType".into(),
                Value::String("organization".into()),
            ),
        ]);
        if let Some(metadata) = metadata {
            provider_metadata.extend(metadata.clone());
        }
        let mut request = Map::from_iter([(
            "meta_data".into(),
            Value::Object(provider_metadata),
        )]);
        if let Some(provider) = options
            .organization
            .as_ref()
            .and_then(|organization| organization.get_customer_create_params.as_ref())
        {
            let extra = provider
                .params(organization, context)
                .await
                .map_err(|error| error.message)?;
            merge_object_spread(&mut request, extra);
        }
        let customer = options
            .client
            .create_customer(Value::Object(request))
            .await
            .map_err(|error| error.message)?;
        if let Some(winner) = store
            .organization_customer_id(organization_id)
            .await
            .map_err(|error| error.to_string())?
        {
            if let Err(error) = options.client.delete_customer(&customer.id).await {
                tracing::warn!(customer_id = %customer.id, %error, "Failed to clean up duplicate Chargebee customer");
            }
            return Ok(winner);
        }
        store
            .set_organization_customer_id(organization_id, Some(customer.id.clone()))
            .await
            .map_err(|error| error.to_string())?;
        if let Some(callback) = options
            .organization
            .as_ref()
            .and_then(|organization| organization.on_customer_create.as_ref())
        {
            let mut snapshot = organization.clone();
            snapshot.chargebee_customer_id = Some(customer.id.clone());
            callback
                .call(&customer, &snapshot, context)
                .await
                .map_err(|error| error.message)?;
        }
        Ok(customer.id)
    }
    .await;
    result.map_err(|error: String| {
        tracing::error!(%error, "Error creating customer");
        ChargebeeApiError::code(400, ChargebeeErrorCode::UnableToCreateCustomer)
    })
}
