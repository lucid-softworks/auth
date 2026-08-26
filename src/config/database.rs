/// Better Auth `user.fields` physical-column mappings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserFieldMappings {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<String>,
    pub image: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Better Auth `session.fields` physical-column mappings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionFieldMappings {
    pub expires_at: Option<String>,
    pub token: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: Option<String>,
}

/// Better Auth `account.fields` physical-column mappings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountFieldMappings {
    pub issuer: Option<String>,
    pub account_id: Option<String>,
    pub provider_id: Option<String>,
    pub user_id: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<String>,
    pub refresh_token_expires_at: Option<String>,
    pub scope: Option<String>,
    pub password: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Better Auth `verification.fields` physical-column mappings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationFieldMappings {
    pub identifier: Option<String>,
    pub value: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Better Auth `rateLimit.fields` physical-column mappings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitFieldMappings {
    pub key: Option<String>,
    pub count: Option<String>,
    pub last_request: Option<String>,
}
