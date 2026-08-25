//! Native interpreter for Better Auth and SDK schemas bundled by `autumn-js@1.2.53`.
//!
//! Regenerate the checked-in catalog with
//! `node conformance/generate-autumn-schema.mjs` after intentionally changing the pin.

mod catalog;
mod engine;
mod error;
mod selection;
mod transforms;

use serde_json::Value;

pub(crate) use error::SchemaError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    GetOrCreateCustomer,
    GetEntity,
    Attach,
    PreviewAttach,
    UpdateSubscription,
    PreviewUpdateSubscription,
    OpenCustomerPortal,
    CreateReferralCode,
    RedeemReferralCode,
    ListPlans,
    ListEvents,
    AggregateEvents,
    MultiAttach,
    PreviewMultiAttach,
    SetupPayment,
}

impl Operation {
    const fn name(self) -> &'static str {
        match self {
            Self::GetOrCreateCustomer => "getOrCreateCustomer",
            Self::GetEntity => "getEntity",
            Self::Attach => "attach",
            Self::PreviewAttach => "previewAttach",
            Self::UpdateSubscription => "updateSubscription",
            Self::PreviewUpdateSubscription => "previewUpdateSubscription",
            Self::OpenCustomerPortal => "openCustomerPortal",
            Self::CreateReferralCode => "createReferralCode",
            Self::RedeemReferralCode => "redeemReferralCode",
            Self::ListPlans => "listPlans",
            Self::ListEvents => "listEvents",
            Self::AggregateEvents => "aggregateEvents",
            Self::MultiAttach => "multiAttach",
            Self::PreviewMultiAttach => "previewMultiAttach",
            Self::SetupPayment => "setupPayment",
        }
    }
}

#[cfg(any(feature = "axum", test))]
pub(crate) fn normalize_public(value: Value, operation: Operation) -> Result<Value, SchemaError> {
    engine::normalize_root(value, &format!("public:{}", operation.name()))
}

pub(crate) fn normalize_outbound(value: Value, operation: Operation) -> Result<Value, SchemaError> {
    engine::normalize_root(value, &format!("outbound:{}", operation.name()))
}

pub(crate) fn normalize_inbound(value: Value, operation: Operation) -> Result<Value, SchemaError> {
    engine::normalize_root(value, &format!("inbound:{}", operation.name()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn public_schemas_strip_protected_and_unknown_fields_recursively() {
        let normalized = normalize_public(
            json!({
                "customerId": "attacker",
                "planId": "pro",
                "featureQuantities": [{"featureId":"seats","quantity":2,"unknown":true}],
                "unknown": true
            }),
            Operation::Attach,
        )
        .unwrap();
        assert!(normalized.get("customerId").is_none());
        assert!(normalized.get("unknown").is_none());
        assert!(normalized["featureQuantities"][0].get("unknown").is_none());
    }

    #[test]
    fn public_defaults_and_required_object_boundaries_match_better_call() {
        assert_eq!(
            normalize_public(json!({}), Operation::GetOrCreateCustomer).unwrap(),
            json!({"errorOnNotFound":true})
        );
        assert!(normalize_public(Value::Null, Operation::GetOrCreateCustomer).is_err());
        assert!(normalize_public(json!({}), Operation::GetEntity).is_err());
        assert_eq!(
            normalize_public(json!({}), Operation::GetEntity)
                .unwrap_err()
                .public_message(),
            "[body.entityId] Invalid input: expected string, received undefined"
        );
    }

    #[test]
    fn outbound_schemas_remap_nested_fields_and_apply_generated_defaults() {
        assert_eq!(
            normalize_outbound(json!({"customerId":"user_1"}), Operation::ListEvents).unwrap(),
            json!({"start_cursor":"","limit":50,"customer_id":"user_1"})
        );
        assert_eq!(
            normalize_outbound(
                json!({"customerId":"user_1","featureId":"api"}),
                Operation::AggregateEvents,
            )
            .unwrap(),
            json!({"customer_id":"user_1","feature_id":"api","bin_size":"day"})
        );
        assert!(
            normalize_outbound(
                json!({"customerId":"user_1","featureId":"api","maxGroups":1.5}),
                Operation::AggregateEvents,
            )
            .is_err()
        );
        let invalid_range = normalize_outbound(
            json!({"customerId":"user_1","featureId":"api","range":123}),
            Operation::AggregateEvents,
        )
        .unwrap_err()
        .to_string();
        assert!(invalid_range.contains("\"code\": \"invalid_value\""));
        assert!(invalid_range.contains("\"24h\""));

        let invalid_integer = normalize_outbound(
            json!({"customerId":"user_1","featureId":"api","maxGroups":1.5}),
            Operation::AggregateEvents,
        )
        .unwrap_err()
        .to_string();
        assert!(invalid_integer.contains("\"expected\": \"int\""));
        assert!(invalid_integer.contains("\"format\": \"safeint\""));
        assert!(invalid_integer.contains("expected int, received number"));
    }

    #[test]
    fn inbound_schema_projects_wire_objects_and_preserves_record_keys() {
        let response = json!({
            "id": "entity_1",
            "name": null,
            "customer_id": "customer_1",
            "feature_id": null,
            "created_at": 0,
            "env": "live",
            "subscriptions": [],
            "purchases": [],
            "balances": {},
            "flags": {"dynamic_flag": {"id":"flag_1","feature_id":"feature_1"}},
            "provider_only": true
        });
        let normalized = normalize_inbound(response, Operation::GetEntity).unwrap();
        assert_eq!(normalized["customerId"], "customer_1");
        assert!(normalized.get("providerOnly").is_none());
        assert_eq!(
            normalized["flags"]["dynamic_flag"]["featureId"],
            "feature_1"
        );
    }

    #[test]
    fn every_operation_has_all_three_generated_roots() {
        let operations = [
            Operation::GetOrCreateCustomer,
            Operation::GetEntity,
            Operation::Attach,
            Operation::PreviewAttach,
            Operation::UpdateSubscription,
            Operation::PreviewUpdateSubscription,
            Operation::OpenCustomerPortal,
            Operation::CreateReferralCode,
            Operation::RedeemReferralCode,
            Operation::ListPlans,
            Operation::ListEvents,
            Operation::AggregateEvents,
            Operation::MultiAttach,
            Operation::PreviewMultiAttach,
            Operation::SetupPayment,
        ];
        for operation in operations {
            for prefix in ["public", "outbound", "inbound"] {
                assert!(
                    catalog::CATALOG
                        .roots
                        .contains_key(&format!("{prefix}:{}", operation.name())),
                    "missing {prefix} root for {}",
                    operation.name()
                );
            }
        }
    }
}
