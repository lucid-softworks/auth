use crate::{PluginEndpoint, PluginHttpMethod};
use std::borrow::Cow;

const fn endpoint(path: &'static str, client_method: &'static str) -> PluginEndpoint {
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed(path),
        client_method,
    }
}

pub(crate) const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint("/autumn/getOrCreateCustomer", "getOrCreateCustomer"),
    endpoint("/autumn/getEntity", "getEntity"),
    endpoint("/autumn/attach", "attach"),
    endpoint("/autumn/previewAttach", "previewAttach"),
    endpoint("/autumn/updateSubscription", "updateSubscription"),
    endpoint(
        "/autumn/previewUpdateSubscription",
        "previewUpdateSubscription",
    ),
    endpoint("/autumn/openCustomerPortal", "openCustomerPortal"),
    endpoint("/autumn/createReferralCode", "createReferralCode"),
    endpoint("/autumn/redeemReferralCode", "redeemReferralCode"),
    endpoint("/autumn/listPlans", "listPlans"),
    endpoint("/autumn/listEvents", "listEvents"),
    endpoint("/autumn/aggregateEvents", "aggregateEvents"),
    endpoint("/autumn/multiAttach", "multiAttach"),
    endpoint("/autumn/previewMultiAttach", "previewMultiAttach"),
    endpoint("/autumn/setupPayment", "setupPayment"),
];
