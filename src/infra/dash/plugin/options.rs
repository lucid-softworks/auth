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

/// Organization-membership projection policy for managed SCIM directories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashDirectoryMembershipProjection {
    pub enabled: bool,
    pub role: String,
}

impl Default for DashDirectoryMembershipProjection {
    fn default() -> Self {
        Self {
            enabled: true,
            role: "member".into(),
        }
    }
}

/// Opt-in Better Auth Infrastructure managed-directory control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashManagedDirectorySync {
    pub enabled: bool,
    pub sso_pairing: bool,
    pub membership_projection: DashDirectoryMembershipProjection,
}

impl Default for DashManagedDirectorySync {
    fn default() -> Self {
        Self {
            enabled: false,
            sso_pairing: true,
            membership_projection: DashDirectoryMembershipProjection::default(),
        }
    }
}

/// Native inputs corresponding to the pinned `dash()` options owned by this endpoint family.
#[derive(Clone, Debug, Default)]
pub struct DashOptions {
    pub connection: InfraConnectionOptions,
    pub activity_tracking: DashActivityTracking,
    pub managed_directory_sync: DashManagedDirectorySync,
}
