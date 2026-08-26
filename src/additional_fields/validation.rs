use super::AdditionalFieldSet;
use crate::{AuthError, DatabaseModel};

pub(crate) fn validate_field_names(
    model: &str,
    configured: &AdditionalFieldSet,
    reserved: &[&str],
) -> Result<(), AuthError> {
    if configured.iter().any(|(name, field)| {
        name.trim().is_empty()
            || reserved.contains(&name.as_str())
            || name.chars().any(|character| character.is_control())
            || field.field_name.as_ref().is_some_and(|field_name| {
                field_name.trim().is_empty() || field_name.chars().any(char::is_control)
            })
            || field
                .static_default_value()
                .is_some_and(|value| !field.accepts(value))
    }) {
        return Err(AuthError::InvalidConfiguration(format!(
            "{model} additional field names must be non-empty and must not replace core fields"
        )));
    }
    Ok(())
}

pub(crate) fn reserved_field_names(model: DatabaseModel) -> &'static [&'static str] {
    match model {
        DatabaseModel::User => &[
            "id",
            "name",
            "email",
            "emailVerified",
            "image",
            "createdAt",
            "updatedAt",
            "username",
            "displayUsername",
            "isAnonymous",
            "role",
            "banned",
            "banReason",
            "banExpires",
            "twoFactorEnabled",
        ],
        DatabaseModel::Session => &[
            "id",
            "token",
            "userId",
            "expiresAt",
            "createdAt",
            "updatedAt",
            "ipAddress",
            "userAgent",
            "impersonatedBy",
        ],
        DatabaseModel::Account => &[
            "id",
            "userId",
            "accountId",
            "providerId",
            "accessToken",
            "refreshToken",
            "idToken",
            "accessTokenExpiresAt",
            "refreshTokenExpiresAt",
            "scope",
            "password",
            "createdAt",
            "updatedAt",
        ],
        DatabaseModel::Verification => &[
            "id",
            "identifier",
            "value",
            "expiresAt",
            "createdAt",
            "updatedAt",
        ],
        DatabaseModel::Organization => &[
            "id",
            "name",
            "slug",
            "logo",
            "metadata",
            "createdAt",
            "updatedAt",
        ],
    }
}
