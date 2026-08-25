use super::{input, support};
use crate::chargebee::ChargebeeSubscription;
use axum::http::HeaderMap;
use chrono::{Days, Duration, Local, LocalResult, Offset, TimeZone};
use serde_json::{Map, Value};

pub(super) fn trial_end(
    input: &input::CreateInput,
    prevent_duplicate_trials: bool,
    plan: Option<&crate::chargebee::ChargebeePlan>,
    existing: &[ChargebeeSubscription],
) -> Option<f64> {
    if let Some(trial_end) = input.trial_end.filter(|value| *value != 0.0) {
        return Some(trial_end);
    }
    let days = plan?.free_trial.as_ref()?.days;
    if days == 0.0
        || (prevent_duplicate_trials
            && existing
                .iter()
                .any(|subscription| subscription.trial_start.is_some()))
    {
        return None;
    }
    local_calendar_trial_end(Local::now(), days)
}

fn local_calendar_trial_end(now: chrono::DateTime<Local>, days: f64) -> Option<f64> {
    if !days.is_finite() {
        tracing::warn!(
            days,
            "Chargebee free-trial days produced an invalid JavaScript date"
        );
        return None;
    }
    let whole_days = days.floor();
    if whole_days < i64::MIN as f64 || whole_days > i64::MAX as f64 {
        return None;
    }
    let target_date = if whole_days.is_sign_negative() {
        now.date_naive()
            .checked_sub_days(Days::new(whole_days.abs() as u64))?
    } else {
        now.date_naive()
            .checked_add_days(Days::new(whole_days as u64))?
    };
    let naive = target_date.and_time(now.time());
    let target = match Local.from_local_datetime(&naive) {
        LocalResult::Single(value) => value,
        LocalResult::Ambiguous(first, _) => first,
        LocalResult::None => resolve_dst_gap(naive)?,
    };
    Some(target.timestamp() as f64)
}

fn resolve_dst_gap(naive: chrono::NaiveDateTime) -> Option<chrono::DateTime<Local>> {
    let before = neighboring_offset(naive, -1)?;
    let after = neighboring_offset(naive, 1)?;
    let normalized = normalize_gap(naive, before, after)?;
    match Local.from_local_datetime(&normalized) {
        LocalResult::Single(value) => Some(value),
        LocalResult::Ambiguous(first, _) => Some(first),
        LocalResult::None => None,
    }
}

fn neighboring_offset(naive: chrono::NaiveDateTime, direction: i32) -> Option<i32> {
    (1..=2_880).find_map(|minutes| {
        let candidate = naive
            .checked_add_signed(Duration::minutes(i64::from(direction) * i64::from(minutes)))?;
        match Local.from_local_datetime(&candidate) {
            LocalResult::Single(value) => Some(value.offset().fix().local_minus_utc()),
            LocalResult::Ambiguous(first, _) => Some(first.offset().fix().local_minus_utc()),
            LocalResult::None => None,
        }
    })
}

fn normalize_gap(
    naive: chrono::NaiveDateTime,
    before_offset: i32,
    after_offset: i32,
) -> Option<chrono::NaiveDateTime> {
    let gap = after_offset.checked_sub(before_offset)?;
    (gap > 0)
        .then(|| naive.checked_add_signed(Duration::seconds(i64::from(gap))))
        .flatten()
}

pub(super) fn request(
    service: &crate::AuthService,
    headers: &HeaderMap,
    input: &input::CreateInput,
    customer_id: &str,
    subscription: &ChargebeeSubscription,
    quantity: f64,
    trial_end: Option<f64>,
) -> Map<String, Value> {
    let items = input
        .item_price_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "item_price_id": id,
                "quantity": support::json_number(quantity),
            })
        })
        .collect::<Vec<_>>();
    let callback = format!(
        "/subscription/success?callbackURL={}&subscriptionId={}",
        support::encode_component(&input.success_url),
        support::encode_component(&subscription.id.to_string()),
    );
    let mut request = Map::from_iter([
        ("subscription_items".into(), Value::Array(items)),
        ("customer".into(), serde_json::json!({"id": customer_id})),
    ]);
    if let Some(trial_end) = trial_end {
        request.insert(
            "subscription".into(),
            serde_json::json!({"trial_end": support::json_number(trial_end)}),
        );
    }
    request.insert(
        "redirect_url".into(),
        Value::String(support::absolute_url(service, headers, &callback)),
    );
    request.insert(
        "cancel_url".into(),
        Value::String(support::absolute_url(service, headers, &input.cancel_url)),
    );
    request
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chargebee::{
        ChargebeeFreeTrial, ChargebeePlan, ChargebeePlanType, ChargebeeSubscription,
    };
    use chrono::Utc;

    fn input() -> input::CreateInput {
        input::CreateInput {
            item_price_ids: vec!["price".into()],
            success_url: "/success".into(),
            cancel_url: "/cancel".into(),
            return_url: None,
            reference_id: None,
            customer_type: input::CustomerType::User,
            seats: None,
            metadata: None,
            disable_redirect: false,
            trial_end: Some(0.0),
        }
    }

    fn plan() -> ChargebeePlan {
        ChargebeePlan {
            name: "Pro".into(),
            item_price_id: "price".into(),
            item_id: None,
            item_family_id: None,
            plan_type: ChargebeePlanType::Plan,
            billing_cycles: None,
            free_trial: Some(ChargebeeFreeTrial { days: 7.0 }),
            limits: None,
        }
    }

    #[test]
    fn duplicate_trial_scan_and_zero_request_follow_javascript_truthiness() {
        let mut prior = ChargebeeSubscription::future("user", Utc::now());
        prior.trial_start = Some(Utc::now());
        assert!(trial_end(&input(), true, Some(&plan()), &[prior]).is_none());
        assert!(trial_end(&input(), false, Some(&plan()), &[]).is_some());
    }

    #[test]
    fn fractional_trial_days_use_calendar_floor_instead_of_elapsed_hours() {
        let now = Local.with_ymd_and_hms(2026, 8, 25, 12, 0, 0).unwrap();
        assert_eq!(
            local_calendar_trial_end(now, 1.5),
            local_calendar_trial_end(now, 1.0),
        );
    }

    #[test]
    fn nonexistent_local_time_is_shifted_forward_by_the_offset_gap() {
        let naive = chrono::NaiveDate::from_ymd_opt(2026, 3, 29)
            .unwrap()
            .and_hms_opt(1, 30, 0)
            .unwrap();
        assert_eq!(
            normalize_gap(naive, 0, 3_600),
            Some(
                chrono::NaiveDate::from_ymd_opt(2026, 3, 29)
                    .unwrap()
                    .and_hms_opt(2, 30, 0)
                    .unwrap()
            ),
        );
    }
}
