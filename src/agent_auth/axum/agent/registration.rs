mod claim;
mod handlers;
mod register;
mod support;

pub(in crate::agent_auth::axum) use handlers::{claim, register};
pub(in crate::agent_auth::axum::agent) use support::build_grants;
