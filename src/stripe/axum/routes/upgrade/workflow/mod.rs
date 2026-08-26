mod existing;
mod new_checkout;
mod policy;

use super::customer;
use crate::{
    AuthService, CheckoutSessionResponse, CustomerType, SessionWithUser, StripeCallbackContext,
    StripeError, StripeErrorCode, StripePlan, StripePlugin, StripeSubscription,
    StripeSubscriptionItem, Subscription, SubscriptionConfiguration, SubscriptionStatus,
    UpgradeSubscriptionInput, UrlRedirectResponse,
};
use serde_json::json;

pub(super) enum UpgradeOutcome {
    Url(UrlRedirectResponse),
    Checkout(Box<CheckoutSessionResponse<crate::StripeCheckoutSession>>),
}

struct CustomerState {
    customer_type: CustomerType,
    customer_id: String,
    automatic_seats: bool,
    member_count: f64,
    callback_user_customer_id: Option<String>,
}

struct CurrentState {
    local_active: Option<Subscription>,
    stripe_active: Option<StripeSubscription>,
    plan_item: Option<StripeSubscriptionItem>,
    incomplete: Option<Subscription>,
}

struct SelectedPrice {
    id: String,
    metered: bool,
}

pub(super) async fn execute(
    service: &AuthService,
    plugin: &StripePlugin,
    session: &SessionWithUser,
    reference_id: &str,
    input: &UpgradeSubscriptionInput,
    callback_context: &StripeCallbackContext,
) -> Result<UpgradeOutcome, StripeError> {
    enforce_subscription_policy(plugin, session)?;
    let plan = plugin
        .options
        .plan_by_name(&input.plan)
        .await
        .map_err(policy::callback_error)?
        .ok_or_else(|| policy::known(400, StripeErrorCode::SubscriptionPlanNotFound))?;
    let selected = select_local(plugin, reference_id, input.subscription_id.as_deref()).await?;
    let customer = prepare_customer(
        service,
        plugin,
        session,
        reference_id,
        input,
        callback_context,
        &plan,
        selected.as_ref(),
    )
    .await?;
    let current =
        load_current(plugin, input, reference_id, selected, &customer.customer_id).await?;
    let price = requested_price(plugin, input, &plan).await?;
    policy::reject_duplicate(
        current.local_active.as_ref(),
        &input.plan,
        input.seats,
        customer.automatic_seats,
        current
            .plan_item
            .as_ref()
            .map(|item| item.price.id.as_str()),
        &price.id,
    )?;
    dispatch(
        service,
        plugin,
        session,
        input,
        callback_context,
        reference_id,
        plan,
        customer,
        current,
        price,
    )
    .await
}

fn enforce_subscription_policy(
    plugin: &StripePlugin,
    session: &SessionWithUser,
) -> Result<(), StripeError> {
    let SubscriptionConfiguration::Enabled(options) = &plugin.options.subscription else {
        return Err(policy::known(400, StripeErrorCode::SubscriptionNotFound));
    };
    if options.require_email_verification && !session.user.email_verified {
        return Err(policy::known(
            400,
            StripeErrorCode::EmailVerificationRequired,
        ));
    }
    Ok(())
}

async fn select_local(
    plugin: &StripePlugin,
    reference_id: &str,
    stripe_id: Option<&str>,
) -> Result<Option<Subscription>, StripeError> {
    let Some(stripe_id) = stripe_id else {
        return Ok(None);
    };
    plugin
        .store
        .find_subscription_by_stripe_id(stripe_id)
        .await
        .map_err(policy::store_error)?
        .filter(|subscription| subscription.reference_id == reference_id)
        .map(Some)
        .ok_or_else(|| policy::known(400, StripeErrorCode::SubscriptionNotFound))
}

#[allow(clippy::too_many_arguments)]
async fn prepare_customer(
    service: &AuthService,
    plugin: &StripePlugin,
    session: &SessionWithUser,
    reference_id: &str,
    input: &UpgradeSubscriptionInput,
    callback_context: &StripeCallbackContext,
    plan: &StripePlan,
    selected: Option<&Subscription>,
) -> Result<CustomerState, StripeError> {
    let callback_user_customer_id = plugin
        .store
        .user_customer_id(&session.user.id)
        .await
        .map_err(policy::store_error)?;
    let customer_type = input.effective_customer_type();
    let automatic_seats =
        plan.seat_price_id.is_some() && customer_type == CustomerType::Organization;
    let customer_needed = selected
        .and_then(|subscription| subscription.stripe_customer_id.as_ref())
        .is_none();
    let (organization, member_count) = policy::organization_context(
        service,
        reference_id,
        customer_type,
        customer_needed,
        automatic_seats,
    )
    .await?;
    let metadata = customer::request_metadata(input);
    let customer_id = customer::resolve(customer::CustomerArguments {
        plugin,
        session,
        selected_subscription: selected,
        customer_type,
        reference_id,
        organization: organization.as_ref(),
        metadata: &metadata,
        callback_context,
    })
    .await
    .map_err(|()| policy::known(400, StripeErrorCode::UnableToCreateCustomer))?;
    Ok(CustomerState {
        customer_type,
        customer_id,
        automatic_seats,
        member_count,
        callback_user_customer_id,
    })
}

async fn load_current(
    plugin: &StripePlugin,
    input: &UpgradeSubscriptionInput,
    reference_id: &str,
    selected: Option<Subscription>,
    customer_id: &str,
) -> Result<CurrentState, StripeError> {
    let subscriptions = match selected.clone() {
        Some(subscription) => vec![subscription],
        None => plugin
            .store
            .list_subscriptions(reference_id)
            .await
            .map_err(policy::store_error)?,
    };
    let local_active = subscriptions
        .iter()
        .find(|subscription| subscription.is_active_or_trialing())
        .cloned();
    let page = plugin
        .options
        .client
        .list_subscriptions(json!({ "customer": customer_id }))
        .await
        .map_err(policy::uncaught_provider_error)?;
    let stripe_active = page
        .data
        .into_iter()
        .filter(StripeSubscription::is_active_or_trialing)
        .find(|subscription| {
            matches_selected(
                subscription,
                input,
                selected.as_ref(),
                local_active.as_ref(),
            )
        });
    let plan_item = match &stripe_active {
        Some(subscription) => policy::resolve_plan_item(plugin, &subscription.items.data)
            .await?
            .map(|(item, _)| item),
        None => None,
    };
    let incomplete = subscriptions
        .iter()
        .find(|subscription| subscription.status == SubscriptionStatus::Incomplete)
        .cloned();
    Ok(CurrentState {
        local_active,
        stripe_active,
        plan_item,
        incomplete,
    })
}

fn matches_selected(
    stripe: &StripeSubscription,
    input: &UpgradeSubscriptionInput,
    selected: Option<&Subscription>,
    local_active: Option<&Subscription>,
) -> bool {
    if selected
        .and_then(|subscription| subscription.stripe_subscription_id.as_deref())
        .is_some()
        || input.subscription_id.is_some()
    {
        return selected
            .and_then(|subscription| subscription.stripe_subscription_id.as_deref())
            .is_some_and(|id| stripe.id == id)
            || input
                .subscription_id
                .as_deref()
                .is_some_and(|id| stripe.id == id);
    }
    local_active
        .and_then(|subscription| subscription.stripe_subscription_id.as_deref())
        .is_some_and(|id| stripe.id == id)
}

async fn requested_price(
    plugin: &StripePlugin,
    input: &UpgradeSubscriptionInput,
    plan: &StripePlan,
) -> Result<SelectedPrice, StripeError> {
    let (price_id, lookup_key) = if input.annual == Some(true) {
        (
            plan.annual_discount_price_id.as_deref(),
            plan.annual_discount_lookup_key.as_deref(),
        )
    } else {
        (plan.price_id.as_deref(), plan.lookup_key.as_deref())
    };
    let resolved = policy::resolve_price(plugin, price_id, lookup_key).await;
    let id = resolved
        .as_ref()
        .map(|price| price.id.clone())
        .or_else(|| price_id.map(str::to_owned))
        .ok_or_else(|| policy::raw_bad_request("Price ID not found for the selected plan"))?;
    let metered = resolved
        .as_ref()
        .and_then(|price| price.recurring.as_ref())
        .and_then(|recurring| recurring.usage_type.as_deref())
        == Some("metered");
    Ok(SelectedPrice { id, metered })
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    service: &AuthService,
    plugin: &StripePlugin,
    session: &SessionWithUser,
    input: &UpgradeSubscriptionInput,
    callback_context: &StripeCallbackContext,
    reference_id: &str,
    plan: StripePlan,
    customer: CustomerState,
    current: CurrentState,
    price: SelectedPrice,
) -> Result<UpgradeOutcome, StripeError> {
    if let Some(active) = current.stripe_active {
        return existing::change(existing::ExistingArguments {
            service,
            plugin,
            input,
            plan: &plan,
            active,
            plan_item: current.plan_item,
            local_active: current.local_active,
            customer_id: &customer.customer_id,
            price_id: &price.id,
            metered: price.metered,
            automatic_seats: customer.automatic_seats,
            member_count: customer.member_count,
        })
        .await;
    }
    new_checkout::create(new_checkout::NewCheckoutArguments {
        service,
        plugin,
        session,
        input,
        callback_context,
        reference_id,
        customer_type: customer.customer_type,
        customer_id: &customer.customer_id,
        plan: &plan,
        active: current.local_active,
        incomplete: current.incomplete,
        callback_user_customer_id: customer.callback_user_customer_id,
        price_id: &price.id,
        metered: price.metered,
        automatic_seats: customer.automatic_seats,
        member_count: customer.member_count,
    })
    .await
}
