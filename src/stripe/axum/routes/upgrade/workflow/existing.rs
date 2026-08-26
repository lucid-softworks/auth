use super::{UpgradeOutcome, policy};
use crate::{
    AuthService, StripeError, StripeErrorCode, StripePlan, StripePlugin, StripeSubscription,
    StripeSubscriptionItem, Subscription, SubscriptionPatch, UpgradeSubscriptionInput,
    UrlRedirectResponse,
};
use serde_json::{Map, Value, json};

pub(super) struct ExistingArguments<'a> {
    pub service: &'a AuthService,
    pub plugin: &'a StripePlugin,
    pub input: &'a UpgradeSubscriptionInput,
    pub plan: &'a StripePlan,
    pub active: StripeSubscription,
    pub plan_item: Option<StripeSubscriptionItem>,
    pub local_active: Option<Subscription>,
    pub customer_id: &'a str,
    pub price_id: &'a str,
    pub metered: bool,
    pub automatic_seats: bool,
    pub member_count: f64,
}

pub(super) async fn change(
    arguments: ExistingArguments<'_>,
) -> Result<UpgradeOutcome, StripeError> {
    let stored = reconcile_stored_subscription(&arguments).await?;
    let plan_item = arguments
        .plan_item
        .as_ref()
        .ok_or_else(|| policy::known(404, StripeErrorCode::SubscriptionNotFound))?;
    release_owned_schedule(&arguments, stored.as_ref()).await?;
    let old_plan = match arguments.local_active.as_ref() {
        Some(subscription) => arguments
            .plugin
            .options
            .plan_by_name(&subscription.plan)
            .await
            .map_err(policy::callback_error)?,
        None => None,
    };
    let reconciliation = super::super::reconciliation::Reconciliation::between(
        old_plan.as_ref(),
        arguments.plan,
        arguments.automatic_seats,
        arguments.member_count,
    );
    let return_url = super::super::super::support::absolute_url(
        arguments.service,
        arguments.input.return_url.as_deref().unwrap_or("/"),
    );
    if arguments.input.schedule_at_period_end {
        return scheduled_change(&arguments, plan_item, &reconciliation, stored, return_url).await;
    }
    if reconciliation.requires_direct_update() {
        return direct_change(&arguments, plan_item, &reconciliation, stored, return_url).await;
    }
    portal_change(&arguments, plan_item, return_url).await
}

async fn reconcile_stored_subscription(
    arguments: &ExistingArguments<'_>,
) -> Result<Option<Subscription>, StripeError> {
    let mut stored = arguments
        .plugin
        .store
        .find_subscription_by_stripe_id(&arguments.active.id)
        .await
        .map_err(policy::store_error)?;
    if stored.is_none()
        && let Some(local) = arguments.local_active.as_ref()
    {
        stored = arguments
            .plugin
            .store
            .update_subscription(
                local.id,
                SubscriptionPatch {
                    stripe_subscription_id: Some(Some(arguments.active.id.clone())),
                    ..SubscriptionPatch::default()
                },
            )
            .await
            .map_err(policy::store_error)?
            .or_else(|| Some(local.clone()));
    }
    Ok(stored)
}

async fn scheduled_change(
    arguments: &ExistingArguments<'_>,
    plan_item: &StripeSubscriptionItem,
    reconciliation: &super::super::reconciliation::Reconciliation,
    stored: Option<Subscription>,
    return_url: String,
) -> Result<UpgradeOutcome, StripeError> {
    let schedule = arguments
        .plugin
        .options
        .client
        .create_subscription_schedule(json!({ "from_subscription": arguments.active.id }))
        .await
        .map_err(policy::provider_error)?;
    let current = schedule
        .phases
        .first()
        .ok_or_else(|| policy::raw_bad_request("Subscription schedule has no phases"))?;
    let next_items = reconciliation.scheduled_items(
        current,
        Some(&plan_item.price.id),
        arguments.price_id,
        base_quantity(arguments),
        arguments.metered,
    );
    let phases = schedule_phases(current, next_items);
    arguments
        .plugin
        .options
        .client
        .update_subscription_schedule(
            &schedule.id,
            json!({
                "metadata": { "source": "@better-auth/stripe" },
                "end_behavior": "release",
                "phases": phases,
            }),
        )
        .await
        .map_err(policy::provider_error)?;
    if let Some(stored) = stored {
        arguments
            .plugin
            .store
            .update_subscription(
                stored.id,
                SubscriptionPatch {
                    stripe_schedule_id: Some(Some(schedule.id)),
                    ..SubscriptionPatch::default()
                },
            )
            .await
            .map_err(policy::store_error)?;
    }
    Ok(url_outcome(return_url, arguments.input.disable_redirect))
}

fn schedule_phases(current: &crate::StripeSchedulePhase, next_items: Vec<Value>) -> Vec<Value> {
    let mut current_phase = Map::from_iter([
        (
            "items".into(),
            Value::Array(super::super::reconciliation::current_phase_items(current)),
        ),
        ("start_date".into(), current.start_date.clone()),
    ]);
    if let Some(end) = &current.end_date {
        current_phase.insert("end_date".into(), end.clone());
    }
    let mut next_phase = Map::from_iter([
        ("items".into(), Value::Array(next_items)),
        ("proration_behavior".into(), json!("none")),
    ]);
    if let Some(end) = &current.end_date {
        next_phase.insert("start_date".into(), end.clone());
    }
    vec![Value::Object(current_phase), Value::Object(next_phase)]
}

async fn direct_change(
    arguments: &ExistingArguments<'_>,
    plan_item: &StripeSubscriptionItem,
    reconciliation: &super::super::reconciliation::Reconciliation,
    stored: Option<Subscription>,
    return_url: String,
) -> Result<UpgradeOutcome, StripeError> {
    let items = reconciliation.direct_items(
        &arguments.active.items.data,
        Some(&plan_item.price.id),
        arguments.price_id,
        base_quantity(arguments),
        arguments.metered,
    );
    arguments
        .plugin
        .options
        .client
        .update_subscription(
            &arguments.active.id,
            json!({
                "items": items,
                "proration_behavior": arguments.plan.proration_behavior.as_str(),
            }),
        )
        .await
        .map_err(policy::provider_error)?;
    if let Some(stored) = stored {
        arguments
            .plugin
            .store
            .update_subscription(
                stored.id,
                SubscriptionPatch {
                    plan: Some(arguments.plan.persisted_name()),
                    // Exact upstream quirk: this is zero for user subscriptions.
                    seats: Some(Some(arguments.member_count)),
                    ..SubscriptionPatch::default()
                },
            )
            .await
            .map_err(policy::store_error)?;
    }
    Ok(url_outcome(return_url, arguments.input.disable_redirect))
}

async fn portal_change(
    arguments: &ExistingArguments<'_>,
    plan_item: &StripeSubscriptionItem,
    return_url: String,
) -> Result<UpgradeOutcome, StripeError> {
    let mut item = Map::from_iter([
        ("id".into(), json!(plan_item.id)),
        ("price".into(), json!(arguments.price_id)),
    ]);
    if !arguments.automatic_seats && !arguments.metered {
        item.insert(
            "quantity".into(),
            json!(super::super::checkout::js_or_one(arguments.input.seats)),
        );
    }
    let session = arguments
        .plugin
        .options
        .client
        .create_billing_portal_session(json!({
            "customer": arguments.customer_id,
            "return_url": return_url,
            "flow_data": {
                "type": "subscription_update_confirm",
                "after_completion": {
                    "type": "redirect",
                    "redirect": { "return_url": return_url },
                },
                "subscription_update_confirm": {
                    "subscription": arguments.active.id,
                    "items": [Value::Object(item)],
                },
            },
        }))
        .await
        .map_err(policy::provider_error)?;
    Ok(url_outcome(session.url, arguments.input.disable_redirect))
}

async fn release_owned_schedule(
    arguments: &ExistingArguments<'_>,
    stored: Option<&Subscription>,
) -> Result<(), StripeError> {
    if arguments.active.schedule_id().is_none() {
        return Ok(());
    }
    let schedules = arguments
        .plugin
        .options
        .client
        .list_subscription_schedules(json!({ "customer": arguments.customer_id }))
        .await
        .map_err(policy::uncaught_provider_error)?;
    let schedule = schedules.data.into_iter().find(|schedule| {
        schedule.subscription.as_ref().and_then(object_id) == Some(arguments.active.id.as_str())
            && schedule.status == "active"
            && schedule.metadata.get("source").and_then(Value::as_str)
                == Some("@better-auth/stripe")
    });
    if let Some(schedule) = schedule {
        arguments
            .plugin
            .options
            .client
            .release_subscription_schedule(&schedule.id)
            .await
            .map_err(policy::uncaught_provider_error)?;
        if let Some(stored) = stored {
            arguments
                .plugin
                .store
                .update_subscription(
                    stored.id,
                    SubscriptionPatch {
                        stripe_schedule_id: Some(None),
                        ..SubscriptionPatch::default()
                    },
                )
                .await
                .map_err(policy::store_error)?;
        }
    }
    Ok(())
}

fn base_quantity(arguments: &ExistingArguments<'_>) -> f64 {
    if arguments.automatic_seats {
        1.0
    } else {
        super::super::checkout::js_or_one(arguments.input.seats)
    }
}

fn object_id(value: &Value) -> Option<&str> {
    match value {
        Value::String(id) => Some(id),
        Value::Object(object) => object.get("id").and_then(Value::as_str),
        _ => None,
    }
}

fn url_outcome(url: String, disable_redirect: bool) -> UpgradeOutcome {
    UpgradeOutcome::Url(UrlRedirectResponse {
        url,
        redirect: !disable_redirect,
    })
}
