use crate::{DatabaseRecord, TestHelpers, TestUserOverrides, TestUtilsError};
use uuid::Uuid;

impl TestHelpers<'_> {
    /// Constructs a Better Auth test user without writing it.
    pub fn create_user(&self, overrides: TestUserOverrides) -> crate::AuthUser {
        crate::test_utils::factory::user(
            self.service.generate_id("user"),
            self.service.default_user_role(),
            overrides,
        )
    }

    /// Persists a factory user through the core user adapter and database hooks.
    pub async fn save_user(
        &self,
        mut user: crate::AuthUser,
    ) -> Result<crate::AuthUser, TestUtilsError> {
        user.email = user.email.to_lowercase();
        crate::database_hooks::scope_creation_method("test", async {
            let user = self.service.prepare_user_create(user).await?;
            let user = self.service.store.create_user_without_account(user).await?;
            self.service
                .after_database_create(&DatabaseRecord::User(user.clone()))
                .await?;
            Ok(user)
        })
        .await
    }

    /// Deletes a user through the core adapter; an absent user is a no-op.
    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), TestUtilsError> {
        if let Some(user) = self.service.store.find_user_by_id(user_id).await? {
            self.service.delete_user_record_with_hooks(&user).await?;
        }
        Ok(())
    }
}
