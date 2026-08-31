//! Native MySQL persistence for Better Auth-compatible schemas.
//!
//! SQLx negotiates MySQL's `FOUND_ROWS` capability and initializes its own
//! connections with a `+00:00` session timezone. Caller-supplied pools must
//! preserve that timezone and pass [`MySqlStore::ready`] before serving.

mod adapter;

pub use adapter::{MySqlAdapterConfig, MySqlStore};
