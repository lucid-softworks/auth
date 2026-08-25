#[path = "support/client.rs"]
mod client;
#[path = "support/fixture.rs"]
mod fixture;

pub(crate) use client::{LifecycleCall, LifecycleClient};
pub(crate) use fixture::{Fixture, fixture, get, post};
