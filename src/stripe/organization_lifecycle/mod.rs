mod deletion;
mod name;
mod seats;
#[cfg(test)]
mod test_support;

use super::StripePlugin;
use crate::{AuthError, Organization, OrganizationStore};

impl StripePlugin {
    /// Better Auth's `afterUpdateOrganization` Stripe contribution.
    pub(crate) async fn after_organization_update(&self, organization: &Organization) {
        name::sync(self, organization).await;
    }

    /// Better Auth's `beforeDeleteOrganization` Stripe contribution.
    pub(crate) async fn before_organization_delete(
        &self,
        organization: &Organization,
    ) -> Result<(), AuthError> {
        deletion::guard(self, organization).await
    }

    /// Better Auth's shared `afterAddMember`, `afterRemoveMember`, and
    /// `afterAcceptInvitation` Stripe contribution.
    pub(crate) async fn after_organization_member_change(
        &self,
        organization: &Organization,
        organization_store: &dyn OrganizationStore,
    ) {
        seats::sync(self, organization, organization_store).await;
    }
}
