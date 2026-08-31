//! Shared managed-infrastructure substrate used by Better Auth's `dash()`.
//!
//! Installing the eventual Dash plugin sends credentials, hosted-route JWTs,
//! request identifiers, visitor identifiers, IP addresses, and coarse location
//! data to the configured API and KV origins. Those origins must therefore be
//! trusted. This module does not add dashboard endpoints or durable local
//! storage; endpoint families build on this substrate separately.

mod client;
mod config;
mod events;
mod identification;
mod jwt;
mod model;
mod plugin;
mod projection;
mod tracking;

#[cfg(feature = "axum")]
mod axum;

pub use client::{DashApiClient, DashClientError, DashClientResponse, DashKvClient, DashRequest};
pub use config::{
    ApiOptions, InfraConnectionOptions, KvOptions, KvRetryOptions, ResolvedConnectionOptions,
    ResolvedKvRetryOptions,
};
pub use events::{
    DashEvent, EMITTED_EVENT_TYPES, ORGANIZATION_EVENT_TYPE_ENTRIES, USER_EVENT_TYPE_ENTRIES,
    all_event_types, organization_event_types, user_event_types,
};
pub use identification::{
    Identification, IdentificationContext, IdentificationCookie, IdentificationCountry,
    IdentificationGeo, IdentificationIpOptions, IdentificationLocation, IdentificationRequest,
    IdentificationService,
};
pub use jwt::{DashAuthorizationError, DashJwtVerifier, DashVerifiedClaims};
pub use model::{
    DashAdapterAction, DashAdapterConnector, DashAdapterOperator, DashAdapterSort,
    DashAdapterWhere, DashPeriod, DashSortDirection, DashUserListQuery,
};
pub use plugin::{
    DashActivityTracking, DashDirectoryMembershipProjection, DashManagedDirectorySync, DashOptions,
    DashPlugin,
};

/// Published `@better-auth/infra` compatibility target.
pub const VERSION: &str = "0.4.3";
/// Exact user agent attached to API and KV requests.
pub const USER_AGENT: &str = "@better-auth/infra v0.4.3";
