use crate::{
    CustomerType, SessionWithUser, StripeCallbackContext, StripeCustomer, StripeMetadata,
    StripeOrganizationSnapshot, StripePlugin, Subscription, UpgradeSubscriptionInput,
    escape_search_value, merge_metadata,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

pub(super) struct CustomerArguments<'a> {
    pub plugin: &'a StripePlugin,
    pub session: &'a SessionWithUser,
    pub selected_subscription: Option<&'a Subscription>,
    pub customer_type: CustomerType,
    pub reference_id: &'a str,
    pub organization: Option<&'a StripeOrganizationSnapshot>,
    pub metadata: &'a StripeMetadata,
    pub callback_context: &'a StripeCallbackContext,
}

pub(super) async fn resolve(arguments: CustomerArguments<'_>) -> Result<String, ()> {
    let CustomerArguments {
        plugin,
        session,
        selected_subscription,
        customer_type,
        reference_id,
        organization,
        metadata,
        callback_context,
    } = arguments;
    if let Some(customer_id) =
        selected_subscription.and_then(|subscription| subscription.stripe_customer_id.clone())
    {
        return Ok(customer_id);
    }
    match customer_type {
        CustomerType::User => {
            if let Some(customer_id) = plugin
                .store
                .user_customer_id(&session.user.id)
                .await
                .map_err(log_error)?
            {
                return Ok(customer_id);
            }
            let customer = user_customer(plugin, session, metadata).await?;
            plugin
                .store
                .set_user_customer_id(&session.user.id, Some(customer.id.clone()))
                .await
                .map_err(log_error)?;
            Ok(customer.id)
        }
        CustomerType::Organization => {
            let organization = organization.ok_or(())?;
            let id = Uuid::parse_str(reference_id).map_err(log_error)?;
            if let Some(customer_id) = plugin
                .store
                .organization_customer_id(id)
                .await
                .map_err(log_error)?
            {
                return Ok(customer_id);
            }
            let customer =
                organization_customer(plugin, organization, metadata, callback_context).await?;
            plugin
                .store
                .set_organization_customer_id(id, Some(customer.id.clone()))
                .await
                .map_err(log_error)?;
            Ok(customer.id)
        }
    }
}

async fn user_customer(
    plugin: &StripePlugin,
    session: &SessionWithUser,
    metadata: &StripeMetadata,
) -> Result<StripeCustomer, ()> {
    let user_id = session.user.id.to_string();
    let query = format!(
        "email:\"{}\" AND -metadata[\"customerType\"]:\"organization\"",
        escape_search_value(&session.user.email)
    );
    let mut customer = match plugin
        .options
        .client
        .search_customers(json!({ "query": query, "limit": 1 }))
        .await
    {
        Ok(page) => page.data.into_iter().next(),
        Err(error) => {
            tracing::warn!(message = %error, "Stripe customers.search failed, falling back to customers.list");
            first_listed_customer(
                plugin,
                json!({ "email": session.user.email, "limit": 100 }),
                |customer| {
                    customer
                        .metadata
                        .get("customerType")
                        .and_then(Value::as_str)
                        != Some("organization")
                },
            )
            .await?
        }
    };
    if customer.as_ref().is_some_and(|candidate| {
        let owner = candidate.metadata.get("userId").and_then(Value::as_str);
        (owner.is_some() && owner != Some(user_id.as_str())) || !session.user.email_verified
    }) {
        customer = None;
    }
    if let Some(customer) = customer {
        return Ok(customer);
    }
    let customer_metadata = merge_metadata(
        [metadata],
        [("userId", user_id.as_str()), ("customerType", "user")],
    );
    plugin
        .options
        .client
        .create_customer(json!({
            "email": session.user.email,
            "name": session.user.name,
            "metadata": customer_metadata,
        }))
        .await
        .map_err(log_error)
}

async fn organization_customer(
    plugin: &StripePlugin,
    organization: &StripeOrganizationSnapshot,
    metadata: &StripeMetadata,
    context: &StripeCallbackContext,
) -> Result<StripeCustomer, ()> {
    let customer = find_organization_customer(plugin, organization).await?;
    let created = customer.is_none();
    let customer = match customer {
        Some(customer) => customer,
        None => create_organization_customer(plugin, organization, metadata, context).await?,
    };
    if created {
        notify_organization_customer_created(plugin, organization, &customer, context).await?;
    }
    Ok(customer)
}

async fn find_organization_customer(
    plugin: &StripePlugin,
    organization: &StripeOrganizationSnapshot,
) -> Result<Option<StripeCustomer>, ()> {
    let query = format!(
        "metadata[\"organizationId\"]:\"{}\" AND metadata[\"customerType\"]:\"organization\"",
        organization.id
    );
    Ok(
        match plugin
            .options
            .client
            .search_customers(json!({ "query": query, "limit": 1 }))
            .await
        {
            Ok(page) => page.data.into_iter().next(),
            Err(error) => {
                tracing::warn!(message = %error, "Stripe customers.search failed, falling back to customers.list");
                first_listed_customer(plugin, json!({ "limit": 100 }), |candidate| {
                    candidate
                        .metadata
                        .get("organizationId")
                        .and_then(Value::as_str)
                        == Some(organization.id.as_str())
                        && candidate
                            .metadata
                            .get("customerType")
                            .and_then(Value::as_str)
                            == Some("organization")
                })
                .await?
            }
        },
    )
}

async fn create_organization_customer(
    plugin: &StripePlugin,
    organization: &StripeOrganizationSnapshot,
    metadata: &StripeMetadata,
    context: &StripeCallbackContext,
) -> Result<StripeCustomer, ()> {
    let callback_params = match &plugin.options.organization {
        Some(options) => match &options.get_customer_create_params {
            Some(callback) => callback
                .params(organization, context)
                .await
                .map_err(log_error)?,
            None => Value::Object(Map::new()),
        },
        None => Value::Object(Map::new()),
    };
    let mut params = callback_params.as_object().cloned().unwrap_or_default();
    let callback_metadata = stripe_metadata(params.get("metadata"));
    let merged_metadata = merge_metadata(
        [&callback_metadata, metadata],
        [
            ("organizationId", organization.id.as_str()),
            ("customerType", "organization"),
        ],
    );
    params.insert("name".into(), json!(organization.name));
    params.insert("metadata".into(), json!(merged_metadata));
    plugin
        .options
        .client
        .create_customer(Value::Object(params))
        .await
        .map_err(log_error)
}

async fn notify_organization_customer_created(
    plugin: &StripePlugin,
    organization: &StripeOrganizationSnapshot,
    customer: &StripeCustomer,
    context: &StripeCallbackContext,
) -> Result<(), ()> {
    if let Some(callback) = plugin
        .options
        .organization
        .as_ref()
        .and_then(|options| options.on_customer_create.as_ref())
    {
        let mut linked = organization.clone();
        linked.stripe_customer_id = Some(customer.id.clone());
        callback
            .call(customer, &linked, context)
            .await
            .map_err(log_error)?;
    }
    Ok(())
}

async fn first_listed_customer(
    plugin: &StripePlugin,
    mut params: Value,
    predicate: impl Fn(&StripeCustomer) -> bool,
) -> Result<Option<StripeCustomer>, ()> {
    loop {
        let page = plugin
            .options
            .client
            .list_customers(params.clone())
            .await
            .map_err(log_error)?;
        if let Some(customer) = page.data.iter().find(|customer| predicate(customer)) {
            return Ok(Some(customer.clone()));
        }
        let next = page.data.last().map(|customer| customer.id.clone());
        if !page.has_more || next.is_none() {
            return Ok(None);
        }
        let object = params
            .as_object_mut()
            .expect("customer list params are an object");
        object.insert("starting_after".into(), json!(next));
    }
}

fn stripe_metadata(value: Option<&Value>) -> StripeMetadata {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|metadata| metadata.iter())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub(super) fn request_metadata(input: &UpgradeSubscriptionInput) -> StripeMetadata {
    input
        .metadata
        .as_ref()
        .into_iter()
        .flat_map(|metadata| metadata.iter())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn log_error(error: impl std::fmt::Display) {
    tracing::error!(message = %error, "Unable to create Stripe customer");
}
