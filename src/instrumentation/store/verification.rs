use super::InstrumentedAuthStore;
use crate::{
    AuthError, DatabaseCreate, VerificationStore, VerificationValue,
    instrumentation::{AdapterOperation, with_adapter_operation},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl VerificationStore for InstrumentedAuthStore {
    async fn create_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<VerificationValue, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "verification",
            self.inner.create_verification(value),
        )
        .await
    }

    async fn reserve_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "verification",
            self.inner.reserve_verification(value),
        )
        .await
    }

    async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "verification",
            self.inner.find_verification(identifier),
        )
        .await
    }

    async fn consume_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        with_adapter_operation(
            AdapterOperation::ConsumeOne,
            "verification",
            self.inner.consume_verification(identifier),
        )
        .await
    }

    async fn update_verification(
        &self,
        value: VerificationValue,
    ) -> Result<Option<VerificationValue>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "verification",
            self.inner.update_verification(value),
        )
        .await
    }

    async fn delete_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Delete,
            "verification",
            self.inner.delete_verification(identifier),
        )
        .await
    }

    async fn delete_expired_verifications(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        with_adapter_operation(
            AdapterOperation::DeleteMany,
            "verification",
            self.inner.delete_expired_verifications(now),
        )
        .await
    }
}
