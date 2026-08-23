use super::{UsernameConfig, UsernameError, UsernameValidationTiming};

impl UsernameConfig {
    fn effective_min_length(&self) -> usize {
        if self.min_username_length == 0 {
            3
        } else {
            self.min_username_length
        }
    }

    fn effective_max_length(&self) -> usize {
        if self.max_username_length == 0 {
            30
        } else {
            self.max_username_length
        }
    }

    pub(crate) fn normalize(&self, value: &str) -> String {
        if let Some(normalizer) = &self.username_normalizer {
            normalizer.normalize(value)
        } else if self.normalize_username {
            value.to_lowercase()
        } else {
            value.to_owned()
        }
    }

    pub(crate) fn normalize_display(&self, value: &str) -> String {
        self.display_username_normalizer.as_ref().map_or_else(
            || value.to_owned(),
            |normalizer| normalizer.normalize(value),
        )
    }

    pub(crate) async fn validate_username(&self, value: &str) -> Result<(), UsernameError> {
        let normalized;
        let value = if self.validation_order.username == UsernameValidationTiming::PostNormalization
        {
            normalized = self.normalize(value);
            &normalized
        } else {
            value
        };
        self.validate_username_raw(value).await
    }

    pub(crate) async fn validate_sign_in_username(&self, value: &str) -> Result<(), UsernameError> {
        let normalized;
        let value = if self.validation_order.username == UsernameValidationTiming::PreNormalization
        {
            normalized = self.normalize(value);
            &normalized
        } else {
            value
        };
        self.validate_username_raw(value).await
    }

    pub(crate) async fn validate_availability_username(
        &self,
        value: &str,
    ) -> Result<(), UsernameError> {
        self.validate_username_raw(value).await
    }

    async fn validate_username_raw(&self, value: &str) -> Result<(), UsernameError> {
        let javascript_length = value.encode_utf16().count();
        if javascript_length < self.effective_min_length() {
            return Err(UsernameError::TooShort);
        }
        if javascript_length > self.effective_max_length() {
            return Err(UsernameError::TooLong);
        }
        let valid = match &self.username_validator {
            Some(validator) => validator.is_valid(value).await,
            None => value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '.')
            }),
        };
        if valid {
            Ok(())
        } else {
            Err(UsernameError::Invalid)
        }
    }

    pub(crate) async fn validate_display_username(&self, value: &str) -> Result<(), UsernameError> {
        let Some(validator) = &self.display_username_validator else {
            return Ok(());
        };
        let normalized;
        let value = if self.validation_order.display_username
            == UsernameValidationTiming::PostNormalization
        {
            normalized = self.normalize_display(value);
            &normalized
        } else {
            value
        };
        if validator.is_valid(value).await {
            Ok(())
        } else {
            Err(UsernameError::InvalidDisplayUsername)
        }
    }
}
