#[path = "support/client.rs"]
mod client;
#[path = "support/fixture.rs"]
mod fixture;

pub(crate) use client::{CommetCall, FakeCommetClient};
pub(crate) use fixture::{Fixture, fixture, get, post, post_absent, post_with_content_type};
