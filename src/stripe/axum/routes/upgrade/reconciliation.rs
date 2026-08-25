use crate::{
    CheckoutLineItem, StripePlan, StripeScheduleItem, StripeSchedulePhase, StripeSubscriptionItem,
};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Reconciliation {
    line_item_delta: Vec<(String, i32)>,
    seat_price_replacement: Option<SeatPriceReplacement>,
}

#[derive(Debug, Clone, PartialEq)]
struct SeatPriceReplacement {
    old_price: String,
    new_price: String,
    quantity: f64,
}

impl Reconciliation {
    pub(super) fn between(
        old_plan: Option<&StripePlan>,
        new_plan: &StripePlan,
        auto_managed_seats: bool,
        member_count: f64,
    ) -> Self {
        let seat_price_replacement = auto_managed_seats
            .then(|| {
                Some(SeatPriceReplacement {
                    old_price: old_plan?.seat_price_id.clone()?,
                    new_price: new_plan.seat_price_id.clone()?,
                    quantity: member_count,
                })
            })
            .flatten()
            .filter(|replacement| replacement.old_price != replacement.new_price);
        let mut line_item_delta = Vec::<(String, i32)>::new();
        for line_item in old_plan.into_iter().flat_map(|plan| plan.line_items.iter()) {
            adjust_delta(&mut line_item_delta, line_item, -1);
        }
        for line_item in &new_plan.line_items {
            adjust_delta(&mut line_item_delta, line_item, 1);
        }
        line_item_delta.retain(|(_, delta)| *delta != 0);
        Self {
            line_item_delta,
            seat_price_replacement,
        }
    }

    pub(super) fn requires_direct_update(&self) -> bool {
        self.seat_price_replacement.is_some() || !self.line_item_delta.is_empty()
    }

    pub(super) fn direct_items(
        &self,
        current: &[StripeSubscriptionItem],
        base_price: Option<&str>,
        new_price: &str,
        quantity: f64,
        omit_quantity: bool,
    ) -> Vec<Value> {
        let mut delta = self.line_item_delta.clone();
        let mut remove_quota = removal_quota(&delta);
        let mut updates = Vec::new();
        for item in current {
            let price = item.price.id.as_str();
            if take_removal(&mut remove_quota, price) {
                updates.push(json!({ "id": item.id, "deleted": true }));
                continue;
            }
            if let Some(replacement) = self.replacement(price) {
                updates.push(json!({
                    "id": item.id,
                    "price": replacement.new_price,
                    "quantity": replacement.quantity,
                }));
                continue;
            }
            if Some(price) == base_price {
                let mut update = Map::from_iter([
                    ("id".into(), Value::String(item.id.clone())),
                    ("price".into(), Value::String(new_price.into())),
                ]);
                if !omit_quantity {
                    update.insert("quantity".into(), json!(quantity));
                }
                updates.push(Value::Object(update));
                continue;
            }
            consume_addition(&mut delta, price);
        }
        append_additions(&mut updates, &delta);
        updates
    }

    pub(super) fn scheduled_items(
        &self,
        current: &StripeSchedulePhase,
        base_price: Option<&str>,
        new_price: &str,
        quantity: f64,
        omit_quantity: bool,
    ) -> Vec<Value> {
        let mut delta = self.line_item_delta.clone();
        let mut remove_quota = removal_quota(&delta);
        let mut items = Vec::new();
        for item in &current.items {
            let Some(price) = schedule_price(item) else {
                continue;
            };
            if take_removal(&mut remove_quota, price) {
                continue;
            }
            if let Some(replacement) = self.replacement(price) {
                items.push(json!({
                    "price": replacement.new_price,
                    "quantity": replacement.quantity,
                }));
                continue;
            }
            if Some(price) == base_price {
                let mut updated =
                    Map::from_iter([("price".into(), Value::String(new_price.into()))]);
                if !omit_quantity {
                    updated.insert("quantity".into(), json!(quantity));
                }
                items.push(Value::Object(updated));
                continue;
            }
            let mut preserved = Map::from_iter([("price".into(), Value::String(price.to_owned()))]);
            if let Some(quantity) = item.quantity {
                preserved.insert("quantity".into(), json!(quantity));
            }
            items.push(Value::Object(preserved));
            consume_addition(&mut delta, price);
        }
        append_additions(&mut items, &delta);
        items
    }

    fn replacement(&self, price: &str) -> Option<&SeatPriceReplacement> {
        self.seat_price_replacement
            .as_ref()
            .filter(|replacement| replacement.old_price == price)
    }
}

pub(super) fn current_phase_items(phase: &StripeSchedulePhase) -> Vec<Value> {
    phase
        .items
        .iter()
        .filter_map(|item| {
            let price = schedule_price(item)?;
            let mut value = Map::from_iter([("price".into(), Value::String(price.to_owned()))]);
            if let Some(quantity) = item.quantity {
                value.insert("quantity".into(), json!(quantity));
            }
            Some(Value::Object(value))
        })
        .collect()
}

fn adjust_delta(delta: &mut Vec<(String, i32)>, line_item: &CheckoutLineItem, amount: i32) {
    let Some(price) = line_item.price.as_ref().and_then(Value::as_str) else {
        return;
    };
    if let Some((_, count)) = delta.iter_mut().find(|(stored, _)| stored == price) {
        *count += amount;
    } else {
        delta.push((price.to_owned(), amount));
    }
}

fn removal_quota(delta: &[(String, i32)]) -> HashMap<String, i32> {
    delta
        .iter()
        .filter_map(|(price, count)| (*count < 0).then_some((price.clone(), -*count)))
        .collect()
}

fn take_removal(quota: &mut HashMap<String, i32>, price: &str) -> bool {
    let Some(count) = quota.get_mut(price) else {
        return false;
    };
    if *count == 0 {
        return false;
    }
    *count -= 1;
    true
}

fn consume_addition(delta: &mut [(String, i32)], price: &str) {
    let Some((_, count)) = delta
        .iter_mut()
        .find(|(stored, count)| stored == price && *count > 0)
    else {
        return;
    };
    *count -= 1;
}

fn append_additions(output: &mut Vec<Value>, delta: &[(String, i32)]) {
    for (price, count) in delta {
        for _ in 0..*count {
            output.push(json!({ "price": price }));
        }
    }
}

fn schedule_price(item: &StripeScheduleItem) -> Option<&str> {
    match &item.price {
        Value::String(price) => Some(price),
        Value::Object(price) => price.get("id").and_then(Value::as_str),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BillingInterval, ProrationBehavior, StripePrice, StripeRecurring};
    use serde_json::json;

    #[test]
    fn line_item_deltas_count_string_occurrences_not_quantities() {
        let old = plan(vec![line(Some(json!("addon")), Some(99))]);
        let new = plan(vec![
            line(Some(json!("addon")), Some(1)),
            line(Some(json!("addon")), Some(50)),
            line(Some(json!({ "price_data": "ignored" })), Some(10)),
        ]);
        let result = Reconciliation::between(Some(&old), &new, false, 0.0);
        let updates = result.direct_items(&[], None, "base", 1.0, false);
        assert_eq!(updates, vec![json!({ "price": "addon" })]);
    }

    #[test]
    fn direct_transform_removes_only_configured_quota_and_preserves_unrelated_items() {
        let old = plan(vec![line(Some(json!("remove")), None)]);
        let new = plan(vec![line(Some(json!("add")), None)]);
        let result = Reconciliation::between(Some(&old), &new, false, 0.0);
        let items = vec![item("si_remove", "remove"), item("si_unrelated", "other")];
        assert_eq!(
            result.direct_items(&items, Some("other"), "new-base", 3.0, false),
            vec![
                json!({ "id": "si_remove", "deleted": true }),
                json!({ "id": "si_unrelated", "price": "new-base", "quantity": 3.0 }),
                json!({ "price": "add" }),
            ]
        );
    }

    #[test]
    fn metered_base_update_omits_quantity() {
        let result = Reconciliation::between(None, &plan(vec![]), false, 0.0);
        assert_eq!(
            result.direct_items(&[item("si_base", "old")], Some("old"), "metered", 8.0, true),
            vec![json!({ "id": "si_base", "price": "metered" })]
        );
    }

    #[test]
    fn scheduled_transform_preserves_unrelated_items_and_replaces_seat_price() {
        let mut old = plan(vec![line(Some(json!("old-addon")), None)]);
        old.seat_price_id = Some("old-seat".into());
        let mut new = plan(vec![line(Some(json!("new-addon")), None)]);
        new.seat_price_id = Some("new-seat".into());
        let reconciliation = Reconciliation::between(Some(&old), &new, true, 4.0);
        let phase = StripeSchedulePhase {
            start_date: json!(100),
            end_date: Some(json!(200)),
            items: vec![
                schedule_item("base", Some(1.0)),
                schedule_item("old-seat", Some(2.0)),
                schedule_item("old-addon", None),
                schedule_item("unrelated", Some(9.0)),
            ],
            extra: Map::new(),
        };
        assert_eq!(
            reconciliation.scheduled_items(&phase, Some("base"), "new-base", 1.0, false),
            vec![
                json!({ "price": "new-base", "quantity": 1.0 }),
                json!({ "price": "new-seat", "quantity": 4.0 }),
                json!({ "price": "unrelated", "quantity": 9.0 }),
                json!({ "price": "new-addon" }),
            ]
        );
    }

    fn plan(line_items: Vec<CheckoutLineItem>) -> StripePlan {
        StripePlan {
            name: "pro".into(),
            price_id: Some("base".into()),
            lookup_key: None,
            annual_discount_price_id: None,
            annual_discount_lookup_key: None,
            limits: None,
            group: None,
            seat_price_id: None,
            proration_behavior: ProrationBehavior::CreateProrations,
            line_items,
            free_trial: None,
        }
    }

    fn line(price: Option<Value>, quantity: Option<u64>) -> CheckoutLineItem {
        CheckoutLineItem {
            price,
            quantity,
            extra: Map::new(),
        }
    }

    fn item(id: &str, price: &str) -> StripeSubscriptionItem {
        StripeSubscriptionItem {
            id: id.into(),
            price: StripePrice {
                id: price.into(),
                active: true,
                lookup_key: None,
                recurring: Some(StripeRecurring {
                    interval: BillingInterval::Month,
                    usage_type: None,
                    extra: Map::new(),
                }),
                extra: Map::new(),
            },
            quantity: Some(1.0),
            current_period_start: 0,
            current_period_end: 1,
            extra: Map::new(),
        }
    }

    fn schedule_item(price: &str, quantity: Option<f64>) -> StripeScheduleItem {
        StripeScheduleItem {
            price: json!(price),
            quantity,
            extra: Map::new(),
        }
    }
}
