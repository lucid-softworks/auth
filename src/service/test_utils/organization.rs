use crate::{
    AuthError, Organization, OrganizationMember, TestOrganizationHelpers,
    TestOrganizationOverrides, TestUtilsError,
};
use chrono::Utc;
use uuid::Uuid;

impl TestOrganizationHelpers<'_> {
    /// Constructs an organization fixture without writing it.
    pub fn create_organization(&self, overrides: TestOrganizationOverrides) -> Organization {
        crate::test_utils::factory::organization(
            self.service.generate_id("organization"),
            overrides,
        )
    }

    pub async fn save_organization(
        &self,
        organization: Organization,
    ) -> Result<Organization, TestUtilsError> {
        self.service
            .save_test_organization(organization)
            .await
            .map_err(Into::into)
    }

    pub async fn delete_organization(&self, organization_id: Uuid) -> Result<(), TestUtilsError> {
        self.service
            .delete_test_organization(organization_id)
            .await
            .map_err(Into::into)
    }

    pub async fn add_member(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
        role: Option<String>,
    ) -> Result<OrganizationMember, TestUtilsError> {
        self.service
            .add_test_organization_member(user_id, organization_id, role)
            .await
            .map_err(Into::into)
    }
}

impl super::AuthService {
    pub(super) async fn save_test_organization(
        &self,
        organization: Organization,
    ) -> Result<Organization, AuthError> {
        self.organization_test_store()?
            .raw_insert_organization(organization)
            .await
    }

    pub(super) async fn delete_test_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<(), AuthError> {
        self.organization_test_store()?
            .raw_delete_organization(organization_id)
            .await
    }

    pub(super) async fn add_test_organization_member(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
        role: Option<String>,
    ) -> Result<OrganizationMember, AuthError> {
        let member = OrganizationMember {
            id: self.generate_id("member"),
            organization_id,
            user_id: user_id.to_string(),
            role: role
                .filter(|role| !role.is_empty())
                .unwrap_or_else(|| "member".into()),
            created_at: Utc::now(),
        };
        self.organization_test_store()?
            .raw_insert_member(member)
            .await
    }

    fn organization_test_store(&self) -> Result<&dyn crate::OrganizationStore, AuthError> {
        self.plugins
            .find::<crate::OrganizationPlugin>()
            .map(|plugin| plugin.store.as_ref())
            .ok_or_else(|| {
                AuthError::InvalidConfiguration("the organization plugin is not enabled".into())
            })
    }
}
