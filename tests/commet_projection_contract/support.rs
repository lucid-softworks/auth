#[path = "support/client.rs"]
mod client;
#[path = "support/fixture.rs"]
mod fixture;

pub(crate) use client::ProjectionClient;
pub(crate) use fixture::{fixture, get, post};
