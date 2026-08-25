#[path = "routes/checkout.rs"]
mod checkout;
#[path = "routes/checkout_legacy.rs"]
mod checkout_legacy;
#[path = "routes/checkout_session.rs"]
mod checkout_session;
#[path = "routes/customer.rs"]
mod customer;
#[path = "routes/registration.rs"]
mod registration;
#[path = "routes/usage.rs"]
mod usage;

use lucid_auth::{DodoCheckoutOptions, DodoPaymentsFeature, DodoProduct, DodoProducts};

fn checkout(authenticated_users_only: bool) -> DodoPaymentsFeature {
    DodoPaymentsFeature::Checkout(DodoCheckoutOptions {
        products: Some(DodoProducts::static_products(vec![DodoProduct::new(
            "prod_pro", "pro",
        )])),
        success_url: Some("/checkout-complete".into()),
        authenticated_users_only,
    })
}
