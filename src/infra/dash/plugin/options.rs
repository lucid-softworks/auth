use super::InfraConnectionOptions;
use std::time::Duration;

/// Opt-in activity tracking published by `dash()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DashActivityTracking {
    pub enabled: bool,
    pub update_interval: Duration,
}

impl Default for DashActivityTracking {
    fn default() -> Self {
        Self {
            enabled: false,
            update_interval: Duration::from_millis(300_000),
        }
    }
}

/// Native inputs corresponding to the pinned `dash()` options owned by this endpoint family.
#[derive(Clone, Debug, Default)]
pub struct DashOptions {
    pub connection: InfraConnectionOptions,
    pub activity_tracking: DashActivityTracking,
}
