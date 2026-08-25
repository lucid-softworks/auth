use crate::autumn::{AutumnOperation, schema::Operation};

#[derive(Debug, Clone, Copy)]
pub(super) struct RouteOperation {
    pub transport: AutumnOperation,
    pub schema: Operation,
    pub optional_body: bool,
}

pub(super) const ROUTES: &[(&str, RouteOperation)] = &[
    route(
        "/autumn/getOrCreateCustomer",
        AutumnOperation::GetOrCreateCustomer,
        Operation::GetOrCreateCustomer,
        false,
    ),
    route(
        "/autumn/getEntity",
        AutumnOperation::GetEntity,
        Operation::GetEntity,
        false,
    ),
    route(
        "/autumn/attach",
        AutumnOperation::Attach,
        Operation::Attach,
        false,
    ),
    route(
        "/autumn/previewAttach",
        AutumnOperation::PreviewAttach,
        Operation::PreviewAttach,
        false,
    ),
    route(
        "/autumn/updateSubscription",
        AutumnOperation::UpdateSubscription,
        Operation::UpdateSubscription,
        false,
    ),
    route(
        "/autumn/previewUpdateSubscription",
        AutumnOperation::PreviewUpdateSubscription,
        Operation::PreviewUpdateSubscription,
        false,
    ),
    route(
        "/autumn/openCustomerPortal",
        AutumnOperation::OpenCustomerPortal,
        Operation::OpenCustomerPortal,
        false,
    ),
    route(
        "/autumn/createReferralCode",
        AutumnOperation::CreateReferralCode,
        Operation::CreateReferralCode,
        false,
    ),
    route(
        "/autumn/redeemReferralCode",
        AutumnOperation::RedeemReferralCode,
        Operation::RedeemReferralCode,
        false,
    ),
    route(
        "/autumn/listPlans",
        AutumnOperation::ListPlans,
        Operation::ListPlans,
        true,
    ),
    route(
        "/autumn/listEvents",
        AutumnOperation::ListEvents,
        Operation::ListEvents,
        true,
    ),
    route(
        "/autumn/aggregateEvents",
        AutumnOperation::AggregateEvents,
        Operation::AggregateEvents,
        false,
    ),
    route(
        "/autumn/multiAttach",
        AutumnOperation::MultiAttach,
        Operation::MultiAttach,
        false,
    ),
    route(
        "/autumn/previewMultiAttach",
        AutumnOperation::PreviewMultiAttach,
        Operation::PreviewMultiAttach,
        false,
    ),
    route(
        "/autumn/setupPayment",
        AutumnOperation::SetupPayment,
        Operation::SetupPayment,
        false,
    ),
];

const fn route(
    path: &'static str,
    transport: AutumnOperation,
    schema: Operation,
    optional_body: bool,
) -> (&'static str, RouteOperation) {
    (
        path,
        RouteOperation {
            transport,
            schema,
            optional_body,
        },
    )
}
