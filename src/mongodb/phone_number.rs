use super::{MongoFilter, MongoStore, codec};
use crate::{
    AuthError, AuthUser, DatabaseCreate,
    phone_number::{PhoneNumberStore, PhoneNumberWriteOutcome},
};
use async_trait::async_trait;
use serde_json::{Map, Value, json};

#[async_trait]
impl PhoneNumberStore for MongoStore {
    async fn find_user_by_phone_number(
        &self,
        phone_number: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        require_fields(self)?;
        super::user::find(self, "phoneNumber", phone_number).await
    }

    async fn create_phone_number_user(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError> {
        require_fields(self)?;
        let (mut user, id) = user.into_parts(self)?;
        let phone = user
            .additional_fields
            .get("phoneNumber")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::Storage("phone-number user requires a phone number".into()))?
            .to_owned();
        user.email = user.email.to_lowercase();
        let record = codec::create_record(self, "user", &user, &id)?;
        match self.insert_required_record("user", record).await {
            Ok(record) => codec::decode("user", record).map(PhoneNumberWriteOutcome::Written),
            Err(error) if crate::mongodb::error::is_unique_violation(&error) => {
                if self.find_user_by_phone_number(&phone).await?.is_some() {
                    Ok(PhoneNumberWriteOutcome::AlreadyExists)
                } else {
                    Err(AuthError::UserAlreadyExists)
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn update_user_phone_number(
        &self,
        user_id: &str,
        phone_number: Option<String>,
        verified: bool,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError> {
        require_fields(self)?;
        let values = Map::from_iter([
            ("phoneNumber".into(), json!(phone_number)),
            ("phoneNumberVerified".into(), json!(verified)),
            ("updatedAt".into(), json!(chrono::Utc::now())),
        ]);
        match self
            .update_record("user", &[MongoFilter::equal("id", json!(user_id))], values)
            .await
        {
            Ok(Some(record)) => codec::decode("user", record).map(PhoneNumberWriteOutcome::Written),
            Ok(None) => Ok(PhoneNumberWriteOutcome::NotFound),
            Err(error) if crate::mongodb::error::is_unique_violation(&error) => {
                Ok(PhoneNumberWriteOutcome::AlreadyExists)
            }
            Err(error) => Err(error),
        }
    }
}

fn require_fields(store: &MongoStore) -> Result<(), AuthError> {
    let model = store.physical_schema()?.model("user")?;
    model.quoted_column("phoneNumber")?;
    model.quoted_column("phoneNumberVerified")?;
    Ok(())
}
