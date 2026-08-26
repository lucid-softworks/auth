use super::{UpgradeOutcome, policy};
use crate::{
    AuthService, CheckoutSessionResponse, CustomerType, SessionWithUser, StripeCallbackContext,
    StripeError, StripePlan, StripePlugin, Subscription, SubscriptionConfiguration,
    SubscriptionPatch, SubscriptionStatus, UpgradeSubscriptionInput,
};
use uuid::Uuid;

pub(super) struct NewCheckoutArguments<'a> {
    pub service: &'a AuthService,
    pub plugin: &'a StripePlugin,
    pub session: &'a SessionWithUser,
    pub input: &'a UpgradeSubscriptionInput,
    pub callback_context: &'a StripeCallbackContext,
    pub reference_id: &'a str,
    pub customer_type: CustomerType,
    pub customer_id: &'a str,
    pub plan: &'a StripePlan,
    pub active: Option<Subscription>,
    pub incomplete: Option<Subscription>,
    pub callback_user_customer_id: Option<String>,
    pub price_id: &'a str,
    pub metered: bool,
    pub automatic_seats: bool,
    pub member_count: f64,
}

pub(super) async fn create(
    arguments: NewCheckoutArguments<'_>,
) -> Result<UpgradeOutcome, StripeError> {
    let subscription = prepare_subscription(&arguments).await?;
    let callback = checkout_callback(&arguments, &subscription).await?;
    let free_trial = eligible_for_trial(&arguments).await?;
    let success_endpoint = format!(
        "{}/subscription/success",
        arguments
            .service
            .oauth_base_url()
            .map_err(policy::auth_error)?
    );
    let absolute =
        |value: &str| super::super::super::support::absolute_url(arguments.service, value);
    let user_id = arguments.session.user.id.to_string();
    let params = super::super::checkout::params(super::super::checkout::CheckoutArguments {
        input: arguments.input,
        plan: arguments.plan,
        subscription: &subscription,
        customer_id: Some(arguments.customer_id),
        customer_type: arguments.customer_type,
        user_id: &user_id,
        user_email: &arguments.session.user.email,
        reference_id: arguments.reference_id,
        price_id: arguments.price_id,
        metered: arguments.metered,
        automatic_seats: arguments.automatic_seats,
        member_count: arguments.member_count,
        free_trial,
        callback: callback.clone(),
        success_endpoint: &success_endpoint,
        absolute_success_url: &absolute,
        absolute_cancel_url: &absolute,
    });
    let stripe_session = arguments
        .plugin
        .options
        .client
        .create_checkout_session(params, callback.and_then(|callback| callback.options))
        .await
        .map_err(policy::provider_error)?;
    Ok(UpgradeOutcome::Checkout(Box::new(
        CheckoutSessionResponse {
            session: stripe_session,
            redirect: !arguments.input.disable_redirect,
        },
    )))
}

async fn prepare_subscription(
    arguments: &NewCheckoutArguments<'_>,
) -> Result<Subscription, StripeError> {
    let seats = if arguments.automatic_seats {
        arguments.member_count
    } else {
        super::super::checkout::js_or_one(arguments.input.seats)
    };
    if let Some(active) = arguments.active.clone() {
        return Ok(active);
    }
    if let Some(incomplete) = arguments.incomplete.clone() {
        return arguments
            .plugin
            .store
            .update_subscription(
                incomplete.id,
                SubscriptionPatch {
                    plan: Some(arguments.plan.persisted_name()),
                    seats: Some(Some(seats)),
                    ..SubscriptionPatch::default()
                },
            )
            .await
            .map_err(policy::store_error)
            .map(|updated| updated.unwrap_or(incomplete));
    }
    arguments
        .plugin
        .store
        .create_subscription(Subscription {
            id: Uuid::new_v4(),
            plan: arguments.plan.persisted_name(),
            reference_id: arguments.reference_id.into(),
            stripe_customer_id: Some(arguments.customer_id.into()),
            stripe_subscription_id: None,
            status: SubscriptionStatus::Incomplete,
            period_start: None,
            period_end: None,
            trial_start: None,
            trial_end: None,
            cancel_at_period_end: false,
            cancel_at: None,
            canceled_at: None,
            ended_at: None,
            seats: Some(seats),
            billing_interval: None,
            stripe_schedule_id: None,
        })
        .await
        .map_err(policy::store_error)
}

async fn checkout_callback(
    arguments: &NewCheckoutArguments<'_>,
    subscription: &Subscription,
) -> Result<Option<crate::CheckoutSessionOverrides>, StripeError> {
    let SubscriptionConfiguration::Enabled(options) = &arguments.plugin.options.subscription else {
        unreachable!("upgrade is only called with subscriptions enabled")
    };
    let Some(callback) = &options.checkout_session_params else {
        return Ok(None);
    };
    let user = super::super::super::support::user_snapshot(
        arguments.session,
        arguments.callback_user_customer_id.clone(),
    );
    let session = super::super::super::support::session_snapshot(arguments.session);
    callback
        .params(
            &user,
            &session,
            arguments.plan,
            subscription,
            arguments.callback_context,
        )
        .await
        .map(Some)
        .map_err(policy::callback_error)
}

async fn eligible_for_trial(arguments: &NewCheckoutArguments<'_>) -> Result<bool, StripeError> {
    let trial_used = arguments
        .plugin
        .store
        .list_subscriptions(arguments.reference_id)
        .await
        .map_err(policy::store_error)?
        .iter()
        .any(Subscription::has_trial_history);
    Ok(!trial_used && arguments.plan.free_trial.is_some())
}
