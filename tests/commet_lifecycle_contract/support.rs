#[path = "support/client.rs"]
mod client;
#[path = "support/fixture.rs"]
mod fixture;

pub(crate) use client::{Call, LifecycleClient};
pub(crate) use fixture::{
    CustomerParams, assert_api_error, context, invoke_after_create, invoke_after_update,
    invoke_before_create, plugin, user,
};
