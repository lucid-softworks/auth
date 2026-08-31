//! Native compatibility for `@better-auth/infra@0.4.3` Sentinel.
//!
//! Installing Sentinel enables security and identification egress to the
//! configured Better Auth Infra API and KV origins. It contributes request and
//! database lifecycle hooks, but no endpoint, table, migration, or rate rule.

mod options;
mod plugin;
mod pow;
mod service;
mod validation;
mod lifecycle;
mod database;

#[cfg(feature = "axum")]
mod axum;

pub use options::{
    BooleanSecurityRule, CompromisedPasswordOptions, CredentialStuffingOptions,
    EmailNormalizationOptions, EmailStrictness, EmailValidationOptions, FreeTrialAbuseOptions,
    GeoAction, GeoBlockingOptions, ImpossibleTravelOptions, SecurityAction, SecurityOptions,
    SentinelOptions, StaleUsersOptions, ThresholdConfig, VelocityOptions,
};
pub use plugin::SentinelPlugin;
pub use pow::{
    CHALLENGE_TTL, DEFAULT_DIFFICULTY, PoWChallenge, PoWSolution, decode_pow_challenge,
    encode_pow_solution, solve_pow_challenge, verify_pow_solution,
};
pub use service::{
    CompromisedPasswordResult, SecurityCheck, SecurityVerdict, SentinelSecurityClient,
    VerdictAction,
};
pub use lifecycle::{FreeTrialReservation, ImpossibleTravelResult, StaleUserResult};
pub use validation::{email_normalization_enabled, normalize_email};

/// Published `@better-auth/infra` compatibility target.
pub const VERSION: &str = "0.4.3";
