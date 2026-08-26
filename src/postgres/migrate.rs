use super::{PostgresStore, storage_error};
use crate::AuthError;

impl PostgresStore {
    pub async fn migrate(&self) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('lucid-auth-migrations'))")
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        self.physical_schema()?
            .migrate(&mut transaction, self.resolved_schema()?)
            .await?;
        transaction.commit().await.map_err(storage_error)
    }
}
