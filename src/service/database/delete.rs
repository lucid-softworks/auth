use super::AuthService;
use crate::{AuthError, DatabaseRecord};

impl AuthService {
    pub(in crate::service) async fn delete_session_token_with_hooks(
        &self,
        token: &str,
    ) -> Result<(), AuthError> {
        let record = self
            .find_stored_session(token)
            .await?
            .map(|session| DatabaseRecord::Session(session.session));
        if let Some(record) = &record {
            self.before_database_delete(record).await?;
        }
        self.delete_stored_session_token(token).await?;
        if let Some(record) = &record {
            self.after_database_delete(record).await?;
        }
        Ok(())
    }

    pub(in crate::service) async fn delete_user_record_with_hooks(
        &self,
        user: &crate::AuthUser,
    ) -> Result<(), AuthError> {
        let record = DatabaseRecord::User(user.clone());
        self.before_database_delete(&record).await?;
        self.store.delete_user(&user.id).await?;
        self.after_database_delete(&record).await
    }

    pub(in crate::service) async fn delete_session_id_with_hooks(
        &self,
        session_id: &str,
    ) -> Result<(), AuthError> {
        let record = self
            .find_stored_session_by_id(session_id)
            .await?
            .map(|(_, session)| DatabaseRecord::Session(session));
        if let Some(record) = &record {
            self.before_database_delete(record).await?;
        }
        self.delete_stored_session_id(session_id).await?;
        if let Some(record) = &record {
            self.after_database_delete(record).await?;
        }
        Ok(())
    }

    pub(in crate::service) async fn delete_user_sessions_with_hooks(
        &self,
        user_id: &str,
    ) -> Result<(), AuthError> {
        let records: Vec<_> = self
            .stored_sessions(user_id)
            .await?
            .into_iter()
            .map(|(_, session)| DatabaseRecord::Session(session))
            .collect();
        for record in &records {
            self.before_database_delete(record).await?;
        }
        self.delete_stored_user_sessions(user_id).await?;
        for record in &records {
            self.after_database_delete(record).await?;
        }
        Ok(())
    }
}
