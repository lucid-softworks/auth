#[cfg(feature = "axum")]
mod axum;
mod callbacks;
mod config;
mod endpoints;
mod error;
mod event;
#[cfg(any(feature = "axum", test))]
mod json;
#[cfg(any(feature = "axum", test))]
mod jwt;
mod memory;
mod model;
mod openapi;
mod plugin;
#[cfg(any(feature = "axum", test))]
mod policy;
#[cfg(feature = "postgres")]
mod postgres;
mod request;
mod schema;
mod store;
mod transition;

pub use callbacks::*;
pub use config::*;
pub use error::*;
pub use event::*;
pub use memory::MemoryAgentAuthStore;
pub use model::*;
pub use openapi::*;
pub use plugin::AgentAuthPlugin;
#[cfg(feature = "postgres")]
pub use postgres::PostgresAgentAuthStore;
pub use request::{AgentRequestVerifier, AgentRequestVerifierError, verify_agent_request};
pub use schema::{AgentAuthModelSchema, AgentAuthSchema};
pub use store::{
    AgentAuthStore, AgentClaimedAutonomousAgent, AgentCleanupOutcome, AgentHostEnrollment,
    AgentHostEnrollmentOutcome, AgentHostRotationOutcome, AgentHostSwitchOutcome,
    AgentKeyRotationOutcome, AgentRegistrationBundle, AgentRegistrationOutcome,
    AgentRevocationOutcome, AgentStoreCreateOutcome,
};
pub use transition::*;
