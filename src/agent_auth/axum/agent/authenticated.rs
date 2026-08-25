mod handlers;
mod lifecycle;

pub(in crate::agent_auth::axum) use handlers::{reactivate, revoke, rotate_key, status};
