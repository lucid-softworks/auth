use super::endpoint;
use crate::{PluginEndpoint, PluginHttpMethod};

pub(super) const MANAGEMENT: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Get, "/dash/list-organizations", "listDashOrganizations"),
    endpoint(PluginHttpMethod::Get, "/dash/export-organizations", "exportDashOrganizations"),
    endpoint(PluginHttpMethod::Get, "/dash/organization/:id", "getDashOrganization"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/create", "createDashOrganization"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/update", "updateDashOrganization"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/delete", "deleteDashOrganization"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/delete-many", "deleteManyDashOrganizations"),
    endpoint(PluginHttpMethod::Get, "/dash/organization/options", "getDashOrganizationOptions"),
    endpoint(PluginHttpMethod::Get, "/dash/organization/:id/members", "listDashOrganizationMembers"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/add-member", "addDashMember"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/remove-member", "removeDashMember"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/update-member-role", "updateDashMemberRole"),
    endpoint(PluginHttpMethod::Get, "/dash/organization/:id/teams", "listDashOrganizationTeams"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/create-team", "createDashTeam"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/update-team", "updateDashTeam"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/delete-team", "deleteDashTeam"),
    endpoint(PluginHttpMethod::Get, "/dash/organization/:orgId/teams/:teamId/members", "listDashTeamMembers"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/add-team-member", "addDashTeamMember"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/remove-team-member", "removeDashTeamMember"),
    endpoint(PluginHttpMethod::Get, "/dash/organization/:id/invitations", "listDashOrganizationInvitations"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/invite-member", "inviteDashMember"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/cancel-invitation", "cancelDashInvitation"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/resend-invitation", "resendDashInvitation"),
    endpoint(PluginHttpMethod::Post, "/dash/organization/check-user-by-email", "dashCheckUserByEmail"),
    endpoint(PluginHttpMethod::Get, "/dash/accept-invitation", "dashAcceptInvitation"),
    endpoint(PluginHttpMethod::Post, "/dash/complete-invitation", "dashCompleteInvitation"),
    endpoint(PluginHttpMethod::Get, "/dash/complete-invitation-handoff", "dashCompleteInvitationHandoff"),
    endpoint(PluginHttpMethod::Get, "/dash/complete-invitation-social", "dashCompleteInvitationSocial"),
    endpoint(PluginHttpMethod::Post, "/dash/check-user-exists", "dashCheckUserExists"),
    endpoint(PluginHttpMethod::Post, "/dash/enable-two-factor", "dashEnableTwoFactor"),
    endpoint(PluginHttpMethod::Post, "/dash/complete-two-factor-setup", "dashCompleteTwoFactorSetup"),
    endpoint(PluginHttpMethod::Post, "/dash/view-two-factor-totp-uri", "dashViewTwoFactorTotpUri"),
    endpoint(PluginHttpMethod::Post, "/dash/view-backup-codes", "dashViewBackupCodes"),
    endpoint(PluginHttpMethod::Post, "/dash/disable-two-factor", "dashDisableTwoFactor"),
    endpoint(PluginHttpMethod::Post, "/dash/generate-backup-codes", "dashGenerateBackupCodes"),
];

pub(super) const DIRECTORY_CONTROL_PLANE: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Get,
        "/dash/organization/:id/sso-providers",
        "listDashOrganizationSsoProviders",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/sso-provider/create",
        "createDashSsoProvider",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/sso-provider/update",
        "updateDashSsoProvider",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/sso-provider/request-verification-token",
        "requestDashSsoVerificationToken",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/sso-provider/verify-domain",
        "verifyDashSsoProviderDomain",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/sso-provider/delete",
        "deleteDashSsoProvider",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/sso-provider/mark-domain-verified",
        "markDashSsoProviderDomainVerified",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/organization/:id/directories",
        "listDashOrganizationDirectories",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/directory/create",
        "createDashOrganizationDirectory",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/directory/delete",
        "deleteDashOrganizationDirectory",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/directory/regenerate-token",
        "regenerateDashDirectoryToken",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/organization/:id/directories/:providerId",
        "getDashManagedOrganizationDirectory",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/directories",
        "createDashManagedOrganizationDirectory",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/directories/:providerId/credentials/rotate",
        "rotateDashManagedDirectoryCredential",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/directories/:providerId/credentials/:credentialId/revoke",
        "revokeDashManagedDirectoryCredential",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/organization/:id/directories/:providerId/events",
        "listDashManagedDirectoryEvents",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/directories/:providerId/decommission",
        "decommissionDashManagedOrganizationDirectory",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/organization/:id/directories/:providerId/unpair",
        "unpairDashManagedOrganizationDirectory",
    ),
];
